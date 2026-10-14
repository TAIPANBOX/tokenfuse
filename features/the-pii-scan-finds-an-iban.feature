Feature: The PII scan finds an IBAN, and the digits of a decimal are not a card

  Measured 2026-10-14: on forge an IBAN beside a card and an email was the one
  item the scan missed; on GCP a clean typed answer was refused as a card,
  because a probability's long fraction passed the Luhn check.

  @decided 2026-10-14: an IBAN kind with its country, length and checksum, and
  a card detector that ignores digits inside a decimal number while keeping
  real cards. Invariant 110.

  # @test:the_forge_prompt_finds_the_iban_beside_the_card_and_the_email
  Scenario: The forge prompt yields three kinds
    Given the prompt with an email address, a card number and GB82WEST12345698765432
    Then the scan finds a card, an email address and an IBAN

  # @test:an_iban_written_in_groups_is_one_finding
  # @test:a_masked_iban_reads_as_its_kind
  Scenario: An IBAN in groups of four is one finding, masked as its kind
    Given IBANs of Britain, Germany, France and Norway, compact or in groups
    Then each is one IBAN finding, and masking writes REDACTED:pii_iban

  # @test:a_wrong_checksum_length_or_country_is_not_an_iban
  # @test:iban_shaped_noise_is_rarely_an_iban
  Scenario: Only the checksum, the length and a registered country make an IBAN
    Given a wrong checksum, a wrong length, an unknown country, lower case or a run that continues
    Then none is an IBAN, and random IBAN-shaped strings rarely pass

  # @test:a_probability_in_a_typed_answer_is_not_a_card
  Scenario: A typed answer's probability is not a card
    Given the typed answer the broker relayed on GCP, its probabilities Luhn-valid
    Then the scan finds nothing in it

  # @test:a_card_written_like_a_card_is_still_found
  Scenario: A card written like a card is still found
    Given a card number with spaces, with dashes, plain, or ending a sentence
    Then it is a card
