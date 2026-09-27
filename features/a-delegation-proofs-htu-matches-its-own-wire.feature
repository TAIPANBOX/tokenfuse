Feature: A delegation proof is checked against the door it actually arrived on

  `proxy::handle` serves both the Anthropic door (`/v1/messages`) and the
  OpenAI door (`/v1/chat/completions`), invariant 55's shared enforcement
  path. Until 2026-09-27 it built the URL a DPoP delegation proof's `htu` is
  checked against from a literal `"/v1/messages"`, regardless of which door
  the request actually arrived on.

  On the OpenAI door this was two bugs in one: a proof that correctly named
  the real path, `/v1/chat/completions`, was refused, because the check
  compared it against the wrong URL; and a proof that named the WRONG
  door's path, `/v1/messages`, was wrongly accepted, because it happened to
  match the literal. Each wire's own path is now what its proof is checked
  against.

  # @test:a_proof_naming_the_real_openai_path_is_accepted_on_the_openai_door
  Scenario: A correct proof for the OpenAI door is accepted there
    Given a gateway serving the OpenAI wire with a delegation issuer configured
    When a request presents a delegation proof whose htu names "/v1/chat/completions"
    Then the request is served

  # @test:a_proof_naming_the_anthropic_path_is_refused_on_the_openai_door
  Scenario: A proof for the wrong door is refused on the OpenAI door
    Given a gateway serving the OpenAI wire with a delegation issuer configured
    When a request presents a delegation proof whose htu names "/v1/messages"
    Then the request is refused

  # @test:a_proof_naming_the_real_anthropic_path_is_accepted_on_the_anthropic_door
  Scenario: A correct proof for the Anthropic door is accepted there
    Given a gateway serving the Anthropic wire with a delegation issuer configured
    When a request presents a delegation proof whose htu names "/v1/messages"
    Then the request is served

  # @test:a_proof_naming_the_openai_path_is_refused_on_the_anthropic_door
  Scenario: A proof for the wrong door is refused on the Anthropic door
    Given a gateway serving the Anthropic wire with a delegation issuer configured
    When a request presents a delegation proof whose htu names "/v1/chat/completions"
    Then the request is refused
