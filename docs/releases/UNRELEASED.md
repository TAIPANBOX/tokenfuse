# Unreleased

## Changed

- The delegation door, the agent-token door and the MCP broker's proof door take a list of public origins. `TOKENFUSE_DELEGATION_ORIGINS` and `TOKENFUSE_MCP_PROOF_ORIGINS` are read beside the existing single-origin variables, and a proof is accepted when its `htu` names any of them at the route's path (CLAUDE.md invariant 141).
- A proof whose `htu` carries a fragment is refused at every door. RFC 9449 section 4.3 says an `htu` names a URI without one; the verifier used to trim it away.
- An origin is compared in the form wardryx's agent-token door uses: scheme and host in lower case, the default port written out. `https://host/path` and `https://HOST:443/path` name one origin.

## Upgrade

- A deployment that names one origin and sends proofs for it keeps working unchanged.
- A list with an entry that is not an origin, a trailing comma included, now refuses to start. Before, the broker read the whole value as one origin and refused every proof.

## Not proven

- The list is read at startup, so a change to it needs a restart.
- The rkyv advisory entry in `.cargo/audit.toml` is stale after the `rust_decimal` 1.43.0 lockfile bump on this branch and is left for a follow-up, because removing it changes teeth cases that CI has not run against the new config.
