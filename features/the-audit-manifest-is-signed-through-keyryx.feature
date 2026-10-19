Feature: The audit manifest can be signed by keyryx custody

  The control plane signs a manifest over each org's audit chain tip, so an
  auditor can prove offline that the log ended at an entry, unaltered. The key
  lived in the control plane's own environment, the last of this repository's
  signatures not held by keyryx custody.

  @decided 2026-10-19: TOKENFUSE_CLOUD_AUDIT_SIGNER=keyryx signs the manifest
  through keyryx's sign API with a key keyryx holds, beside today's key in the
  environment; unset keeps today's behaviour; a keyryx that cannot be reached
  when a manifest is signed fails closed for that manifest and says so.

  The choices inside it are @claude: keyryx's answer is verified before it is
  served, and only ES256 is taken; the manifest names keyryx's kid; the failure
  is a 503; a manifest keyryx signed is reused for an unchanged tip for at most
  sixty seconds; the credential is read from a file on every sign; and a signer
  configuration that cannot be used refuses to start.

  # @test:a_manifest_keyryx_signed_verifies_and_names_its_kid
  # @test:an_answer_that_verifies_is_taken_and_its_key_served_uncompressed
  Scenario: A manifest keyryx signed verifies offline and names its kid
    Given the signer is keyryx and keyryx holds an ES256 key granted to the control plane
    When a viewer asks for the org's audit manifest
    Then keyryx is asked to sign exactly the manifest's canonical bytes, with the credential the file holds
    And the manifest verifies offline under the public key keyryx named
    And it names keyryx's kid

  # @test:an_unreachable_keyryx_fails_closed_and_no_other_key_signs_instead
  Scenario: An unreachable keyryx is a manifest not signed
    Given the signer is keyryx and keyryx cannot be reached
    When a viewer asks for the org's audit manifest
    Then the answer is 503 saying keyryx could not be reached
    And no signature is served, and no other key signs instead

  # @test:a_refusing_keyryx_fails_closed_with_its_status
  Scenario: A keyryx that refuses is a manifest not signed
    Given the signer is keyryx and keyryx refuses the sign
    When a viewer asks for the org's audit manifest
    Then the answer is 503 naming the status keyryx answered

  # @test:an_answer_that_does_not_verify_or_is_not_es256_is_never_served
  # @test:a_signature_over_other_bytes_is_refused
  # @test:a_public_key_that_did_not_sign_is_refused
  # @test:an_answer_in_another_algorithm_is_refused
  # @test:an_answer_missing_a_field_is_refused_by_name
  # @test:hostile_answers_never_panic_and_never_verify
  Scenario: An answer that does not verify, or is not ES256, is never served
    Given the signer is keyryx
    When keyryx answers with a signature over other bytes, a key that did not sign, another algorithm, or noise
    Then the answer is 503 saying why, and nothing keyryx answered is served

  # @test:an_unchanged_tip_reuses_the_signed_manifest_and_a_new_tip_signs_again
  # @test:a_reused_manifest_is_signed_again_after_sixty_seconds
  Scenario: An unchanged tip reuses the signed manifest for at most sixty seconds
    Given keyryx signed a manifest for an org
    When a viewer asks again before the tip moves and within sixty seconds
    Then the same manifest is served and keyryx is not asked again
    And a new tip, or sixty seconds, signs again

  # @test:the_credential_file_is_read_on_every_sign
  Scenario: A rotated credential is used at the next sign
    Given the signer is keyryx and its credential file is rewritten with a new credential
    When the next manifest is signed
    Then keyryx is asked with the new credential, without a restart

  # @test:unset_or_env_signs_with_the_in_process_key_as_before
  # @test:an_in_process_manifest_carries_no_kid_member
  # @test:manifest_signature_verifies_and_matches_chain
  # @test:not_configured_returns_404_not_500
  Scenario: Unset, the manifest is signed exactly as before
    Given TOKENFUSE_CLOUD_AUDIT_SIGNER is unset or env
    When a viewer asks for the org's audit manifest
    Then the key in TOKENFUSE_CLOUD_AUDIT_SIGNING_KEY signs it, with no kid member
    And with no key configured the answer is still 404, not configured

  # @test:the_keyryx_signer_with_nothing_else_refuses_to_start
  # @test:a_mistyped_signer_refuses_to_start
  # @test:a_signer_word_it_cannot_read_refuses_to_start
  # @test:keyryx_missing_its_variables_names_each_one
  # @test:keyryx_beside_an_in_process_key_refuses_to_start
  # @test:keyryx_variables_without_the_keyryx_signer_refuse_to_start
  # @test:a_keyryx_url_that_is_not_an_origin_is_refused
  # @test:a_key_name_outside_keyryxs_grammar_or_its_reserved_space_is_refused
  # @test:a_credential_file_that_cannot_be_used_is_refused_and_never_echoed
  # @test:keyryx_with_everything_configured_is_the_keyryx_signer
  Scenario: A signer configuration that cannot be used refuses to start
    Given TOKENFUSE_CLOUD_AUDIT_SIGNER names a word it cannot read, or keyryx with a variable missing or unusable
    And the same holds for keyryx beside a key in the environment, and for a keyryx variable with the signer not keyryx
    When the control plane starts
    Then it exits 2 before it listens, naming each variable at fault and never a credential
