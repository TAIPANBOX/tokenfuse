Feature: The P-256 bytes on the wire are unchanged by a curve library upgrade

  The cloud, the delegation fixture, the DPoP tests and the gateway's
  checkpoint signer use the RustCrypto `p256` crate. Moving it from 0.13 to
  0.14 (with `elliptic-curve` 0.14, `ecdsa` 0.17 and `pkcs8` 0.11) removes
  `crypto-bigint` 0.5.5 and its advisory, RUSTSEC-2026-0387, from the
  lockfile. The upgrade renames APIs (`to_encoded_point` became
  `to_sec1_point`, keys are made through the `Generate` trait), and none of
  that may change a byte another system reads: a JWK's `x` and `y`, an
  RFC 7638 thumbprint, a raw r||s ES256 signature, a SEC1 public key, or the
  PKCS#8 and SEC1 private keys an operator already holds.

  @decided 2026-10-26: the advisories are fixed by upgrading, not by an
  ignore in `.cargo/audit.toml`.

  The expectations below come from RFC 6979 appendix A.2.5 (a P-256 key, its
  public point and its deterministic SHA-256 signatures), with the base64
  forms, the thumbprint and the PEM and DER encodings computed outside this
  repository by Python `cryptography` 50.0.1. Each scenario's test passes on
  both p256 0.13.2 and p256 0.14.0.

  What this does NOT cover: the APNs provider JWT, which uses the same
  signing primitive but mints at the current time and has no fixed-vector
  test; and signatures from real Apple Secure Enclave keys, which no test
  holds. p256 keeps `NORMALIZE_S = false` in 0.14, so a high-S signature
  still verifies, as it did in 0.13; that was read in the crate source, not
  run.

  # @test:the_rfc_6979_key_puts_its_published_point_and_signatures_on_the_wire
  Scenario: The checkpoint key's JWK and signatures are the published bytes
    Given the gateway's checkpoint key built from the RFC 6979 P-256 scalar
    When it writes its public JWK and signs "sample" and "test"
    Then the JWK's x and y are the RFC's coordinates in base64url without padding
    And its kid is the RFC 7638 thumbprint computed outside this repository
    And each signature is the RFC's r followed by s, 64 bytes

  # @test:a_published_rfc_6979_signature_verifies_and_no_other_encoding_of_it_does
  Scenario: A device signature in the published encoding verifies and no other does
    Given the RFC 6979 public point in uncompressed and compressed SEC1
    And the RFC's signature over "sample" as raw r||s
    When the cloud verifies a device signature
    Then the raw r||s signature verifies under both encodings of the key
    And the same signature with its halves swapped is refused
    And the same signature in DER is refused

  # @test:the_rfc_6979_key_loads_from_every_accepted_encoding_and_signs_a_known_manifest
  Scenario: Every accepted encoding of an audit signing key loads and signs the same manifest
    Given the RFC 6979 key as PKCS#8 PEM, SEC1 PEM, PKCS#8 DER, SEC1 DER and a raw scalar
    When each is loaded as the audit signing key and signs the same empty-chain manifest
    Then the manifest's public key is SEC1 uncompressed and the same for all five
    And the manifest's signature is the deterministic one computed outside this repository

  # @test:a_kid_that_is_the_keys_thumbprint_is_taken
  Scenario: A keyryx key's thumbprint is the one keyryx's own code computes
    Given three P-256 keys whose thumbprints were measured from keyryx's Go code
    When the cloud takes the thumbprint of each key keyryx sends
    Then each thumbprint is the measured one, whichever SEC1 encoding was sent

  # @test:the_committed_fixture_is_what_the_writer_writes_byte_for_byte
  Scenario: The committed checkpoint fixture is reproduced byte for byte
    Given the checkpoint fixture written and signed before the upgrade
    When the writer writes the same stream with the same key
    Then every record and every signature is byte for byte the committed one
