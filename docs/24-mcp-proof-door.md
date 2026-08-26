# 24 - the MCP broker's proof door: CIMD client ids and DPoP

Status: shipped, off by default. Block B5 of the 2026-08-25 agent-identity plan.

Invariants 20 and 23 narrowed what is BEHIND the MCP credential-broker's door:
who may reach the port, and which secret they may pull once inside. The
credential ON the door stayed a shared secret in a header. This is the other
half.

Nothing here is on by a default. A broker that sets none of the three variables
below behaves byte for byte as it did before this existed.

## 1. What was wrong with a shared secret

`TOKENFUSE_MCP_KEYS="secret:key_id,..."` is a bearer credential. Whoever holds
the string is the client: from any address, at any time, until somebody notices
and rotates it. It sits in a deployment manifest, an environment variable, a
shell history, a CI log, and in every request on the wire.

That is an odd thing to guard a vault with, and the vault is the point:
invariant 20 states the premise plainly, that whatever reaches this port can
have `{{secret:NAME}}` handles resolved against the whole vault and forwarded
to a configured upstream.

## 2. CIMD, and the judgement about the fetch

`draft-ietf-oauth-client-id-metadata-document` makes a client's identifier an
https URL that resolves to that client's own metadata document. What it buys
here is not authentication. It is that **there is nothing to provision**: an
operator does not mint a secret, hand it over, and then own the problem of it
leaking. The client publishes a document naming its public keys; the operator
allowlists the URL. Rotation is the client republishing.

### The broker never dereferences a client id

CIMD's dereference is a network fetch, and there are two places it could
happen.

**On the request path: never.** The broker already forwards to an upstream MCP
server and may ask a gateway's firewall (docs/07 B.7 level 3). A third fetch,
per request, to a host chosen by the party being authenticated, would make this
door's availability somebody else's website and its latency somebody else's
DNS. It is the same call the estate already made one plane over: CLAUDE.md
invariant 29 keeps delegation verification a library call precisely so a PDP
deciding at a 3.2 ms p50 does not acquire a round trip per decision.

**At configuration time: yes, and that is where it is.** The fetch is one
`curl` in the operator's deploy, writing the documents to the file
`TOKENFUSE_MCP_CLIENT_IDS` names:

```sh
# in your deploy, not in the request path
for id in "$@"; do curl -fsS "$id"; done | jq -s '.' > /etc/tokenfuse/mcp-clients.json
```

Doing the fetch in-process at startup was considered and rejected. It buys
exactly one deploy step; it costs a boot-time dependency on a third party; and
it still needs a restart to pick up a rotated key, so it does not even buy
freshness. `TOKENFUSE_CLOUD_OIDC_JWKS` reached the same conclusion for the same
reason, and says so in its own module doc: static, never fetched.

**The cost of that, stated rather than hidden.** Because this process never
performs the retrieval, it cannot enforce CIMD's self-consistency rule that a
document was served from the URL it claims. The operator's fetch is what
establishes that. An operator who saves the wrong file under the wrong URL gets
the identity they wrote down.

## 3. DPoP, said as narrowly as it is true

An admitted call carries an [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)
proof: a short JWS, signed by the client's private key, carrying the matching
public key, the method and URL of THIS request, the moment, and a unique `jti`.
The broker verifies it, takes the RFC 7638 thumbprint of the key that signed
it, and looks that thumbprint up among the keys the configured clients
published.

**The identity comes from the key, not from anything the caller asserts.** A
call does not say which client it is. That is CLAUDE.md invariant 15's rule one
door over: anything a caller can choose, a caller can change. It also makes the
"claims client A, signs with client B's key" failure unrepresentable rather
than merely checked.

### What it does not do

- **It does not authenticate the agent to the upstream MCP server.** The broker
  forwards with whatever the vault injects, and the upstream sees the broker.
  Nothing is signed on the outbound leg. An upstream that wants to know who is
  calling still learns only that TokenFuse is.
- **It is not a delegation check.** It says nothing about whom the caller acts
  for. That is `vouchryx` and `tokenfuse-cloud`'s `delegation`, which no request
  path in this repository calls yet (invariant 29's own "where it says
  nothing").
- **It does not narrow which secret the caller may pull.** That is invariant
  23's `TOKENFUSE_MCP_SECRET_SCOPES`, a separate axis. Neither substitutes for
  the other.
- **It does not help against a compromised client.** A private key an attacker
  holds is exactly as good as a bearer token they hold. What it removes is the
  value of everything an attacker can capture in flight, or find at rest in a
  log, a shell history, or a manifest.

### Single use matters more here than almost anywhere

`htm` and `htu` pin a proof to one method and one URL, which is most of DPoP's
per-request value on an API with many endpoints. **This broker has one**: every
JSON-RPC method arrives as a POST to the same path. Without a replay cache, a
proof captured from a harmless `tools/list` is a valid credential for
`tools/call` for the rest of its window, and the binding would be a control
that looks exactly like it is working.

So a `jti` is single-use. The cache keeps two generations of two windows each,
so nothing inside the window is forgotten, and it **refuses rather than
forgetting** when it reaches its cap: a replay guard that quietly stops
guarding under pressure is worse than one that is plainly off. Only a caller
whose proof has already verified against a configured client's key ever reaches
the cache, so filling it is something an admitted client can do and a stranger
cannot.

`htu` is compared against `TOKENFUSE_MCP_PROOF_URL` plus the path this server
actually routed, never against a `Host` header. A caller who supplies the host
can make `htu` agree with anything it likes, which turns the check into
decoration.

## 4. Configuration

| Variable | Meaning |
|---|---|
| `TOKENFUSE_MCP_CLIENT_IDS` | A JSON array of client metadata documents, or a path to a file holding one. Unset means the proof door is off. |
| `TOKENFUSE_MCP_PROOF_URL` | The origin clients address this broker at, for example `https://mcp.acme.example`. Required when the above is set. |
| `TOKENFUSE_MCP_REQUIRE_PROOF` | `1` or `true`: a bearer credential alone stops being enough. Off by default. |

A document is the client's own, in CIMD's shape:

```json
[
  {
    "client_id": "https://release-bot.acme.example/mcp-client.json",
    "client_name": "release-bot",
    "jwks": { "keys": [ { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } ] }
  }
]
```

A client presents its proof in the standard `DPoP` header.

**Set but unusable refuses to start**, rather than reading as "off": a
`client_id` that is not an absolute https URL, a document with no `jwks.keys`, a
key of a type this broker cannot verify against, two clients publishing one key,
a file that cannot be read, a missing `TOKENFUSE_MCP_PROOF_URL`. That is the
same conclusion `TOKENFUSE_MCP_KEYS` and `TOKENFUSE_MCP_SECRET_SCOPES` both
reached: reading a typo as "not configured" leaves the door in whatever state
the other variable happens to be in, at the moment an operator believed they had
just tightened it.

A published key of a type the broker cannot verify against is refused rather
than skipped, and that is deliberate strictness. Skipping it would leave the
operator believing they had published something that is honoured, and the
difference would surface only as a client that mysteriously cannot get in.

## 5. Both doors at once, and how that ends

An operator adds the first CIMD client while every existing client still sends
`x-fuse-key`. The composition rule is three sentences and each one is a
decision:

1. **A caller that presents a proof is judged by it.** A broken proof is a
   refusal and never a fall-back to the weaker door, even when the same call
   also carries a good bearer credential. Anything else means an attacker with a
   stolen `x-fuse-key` strips the `DPoP` header, or sends a broken one, and is
   back in the old world. This is `delegation.rs`'s own rule one plane over: a
   bound credential honoured with the binding skipped is a failure that looks
   exactly like it is working.
2. **A caller that presents no proof falls through to the bearer door** while
   one is configured. That is what makes this an addition rather than a breaking
   change.
3. **It is not silent.** With both configured and `TOKENFUSE_MCP_REQUIRE_PROOF`
   off, the broker warns at startup that a captured `x-fuse-key` header is still
   a way in, and names the variable that ends it.

`TOKENFUSE_MCP_REQUIRE_PROOF=1` with no clients configured refuses to start: it
is a door nothing can ever open, and saying so at startup beats discovering it
at the first refused call.

## 6. What the wire says

Nothing. Every refusal at this door is the same `401` with the same body, for
the reason `tokenfuse-cloud`'s `delegation` already documents: a verifier that
narrates which of eight checks failed is an oracle, and here it would tell an
attacker whether a captured proof was still fresh, whether the key was known,
and which server the proof was made for. The operator's own log carries the
reason, because "your proof was replayed" and "no client published that key"
send somebody to different places.

**One honest wart.** That shared `401` body names `x-fuse-key`, because it is
the gateway's own `unauthorized_response` and sharing it is what keeps the two
planes from drifting apart. On a deployment where only the proof door is
configured, it names a header that deployment does not use.

## 7. Where the verifier lives

`crates/dpop` (`tokenfuse-dpop`), a small crate both planes depend on. It holds
the proof verifier, the RFC 7638 thumbprint, the replay cache, and the single
copy of the algorithm allowlist that closes the RS256-to-HS256 downgrade.

It is a crate rather than a module because the gateway must not depend on the
Cloud (that would put the control-plane API surface inside the data-plane
binary) and `tokenfuse-core` must not grow a JWS library (invariant 1 pins its
five dependencies so it stays provable and portable). Invariant 29 asked for one
copy of the algorithm rule; this keeps exactly that and changes only its
address.

## 8. Not done, named rather than hidden

- **No dereference of a `client_id`**, in-process, ever. Section 2 argues it;
  the consequence is that CIMD's self-consistency rule is the operator's to
  establish.
- **The replay cache is per process.** Two brokers behind a load balancer each
  remember their own, so a proof used at one can be replayed at the other inside
  its window. Closing that needs shared state and is a deployment decision.
- **stdio is unaffected.** That transport has no header channel and no port; its
  access control is the operating system's, since the client is the parent
  process. The same is already true of `TOKENFUSE_MCP_KEYS`.
- **No agent-event.** A refusal at this door is a `tracing::warn!`, matching the
  bearer door exactly. Giving it an event type means a new `EventType`, a fixed
  severity, a regenerated `contracts/tokenfuse-constants.json` and a registry row
  in agent-passport SPEC 6.2, which is a decision of its own.
- **`client_id` is not carried into attribution.** An admitted client is logged;
  it does not become a `key_id`, does not reach the ledger, and does not appear
  on any event.
- **Nothing here rate-limits.** A client holding a valid key can call as often as
  it likes, up to the replay cache's cap.
