//! The MCP credential-broker's door, when the credential is a KEY rather than a
//! shared secret.
//!
//! # What was wrong with the door that already exists
//!
//! `TOKENFUSE_MCP_KEYS` ([`crate::clientkeys`]) is a bearer credential: a string
//! in a header. Whoever captures it holds it, from anywhere, until somebody
//! notices and rotates it. CLAUDE.md invariants 20 and 23 have been narrowing
//! what is behind this door (who may reach the port, which secret they may pull
//! once inside) while the credential on the door itself stayed a password.
//!
//! # CIMD: the client id is a URL, and it is not a secret
//!
//! `draft-ietf-oauth-client-id-metadata-document` makes a client's identifier an
//! https URL that resolves to the client's own metadata document. What that buys
//! here is not a login: it is that **there is nothing to provision**. An
//! operator does not mint a secret, hand it to a client, and then own the
//! problem of it leaking; the client publishes a document naming its public
//! keys, and the operator allowlists the URL. Key rotation is the client
//! republishing. Nothing an operator holds is worth stealing.
//!
//! # This broker never dereferences a client id, and that is the decision
//!
//! CIMD's dereference is a network fetch of a URL, and there are exactly two
//! places it could happen.
//!
//! **On the request path: never.** The broker already forwards to an upstream
//! and may ask a gateway's firewall (docs/07 B.7 level 3); a third fetch, per
//! request, to a host chosen by the party being authenticated, would make this
//! door's availability somebody else's website and its latency somebody else's
//! DNS. It is also the same call the estate has already made one plane over:
//! CLAUDE.md invariant 29 keeps delegation verification a library call
//! precisely so a PDP deciding at a 3.2 ms p50 does not acquire a round trip per
//! decision.
//!
//! **At configuration time: yes, and that is where it is.** The fetch is one
//! `curl` in the operator's deploy, writing the documents to the file
//! `TOKENFUSE_MCP_CLIENT_IDS` names. Doing it in-process at startup would buy
//! exactly one deploy step and cost a boot-time dependency on a third party, and
//! it would still need a restart to pick up a rotated key, so it buys nothing
//! there either. `TOKENFUSE_CLOUD_OIDC_JWKS` reached the same conclusion for the
//! same reason and says so in its own module doc.
//!
//! The honest cost is stated rather than hidden: because this process never
//! performs the retrieval, it cannot enforce CIMD's self-consistency rule that a
//! document was served from the URL it claims. The operator's fetch is what
//! establishes that, and an operator who saves the wrong file under the wrong
//! URL gets the identity they wrote down.
//!
//! # DPoP: what it does, said as narrowly as it is true
//!
//! RFC 9449 binds a call to a key. A caller proves, per request, that it holds
//! the private key for a public key one configured client published, for THIS
//! method and path, at about this moment, once.
//!
//! What it does **not** do:
//!
//! - **It does not authenticate the agent to the upstream MCP server.** The
//!   broker forwards with whatever the vault injects; the upstream sees the
//!   broker. Nothing is signed on the outbound leg and this changes nothing
//!   about what the upstream can conclude.
//! - **It is not a delegation check.** It says nothing about whom the caller is
//!   acting for. That is `vouchryx`'s and `tokenfuse-cloud`'s
//!   `delegation::verify_delegation`, which this repository still does not call
//!   from any request path (invariant 29's own "where it says nothing").
//! - **It does not narrow which secret the caller may pull.** That is invariant
//!   23's `TOKENFUSE_MCP_SECRET_SCOPES`, a separate axis, and neither
//!   substitutes for the other.
//! - **It does not help against a compromised client.** A private key an
//!   attacker holds is exactly as good as a bearer token they hold. What it
//!   removes is the value of everything an attacker can capture in FLIGHT or
//!   find at rest in a log, a shell history, or a config file.
//!
//! # Why single-use matters more here than almost anywhere
//!
//! `htm` and `htu` pin a proof to one method and one URL, which is most of DPoP's
//! per-request value on an API with many endpoints. This broker has one: every
//! JSON-RPC method arrives as a POST to the same path. So without a replay cache
//! a proof captured from a harmless `tools/list` is a valid credential for
//! `tools/call` for the rest of its window, and shipping the binding without it
//! would be a control that looks exactly like it is working. See
//! [`tokenfuse_dpop::ReplayCache`].

use std::collections::{HashMap, HashSet};

use tokenfuse_dpop::{thumbprint_of_json, verify_proof, KeyRefusal, ReplayCache, ReplayRefusal};

use crate::clientkeys::ClientKeys;

/// The header carrying an RFC 9449 proof. The RFC spells it `DPoP`; HTTP header
/// names are case-insensitive and axum lowercases them.
pub const PROOF_HEADER: &str = "dpop";

/// How many `jti` values one generation of the replay cache holds.
///
/// Only a caller whose proof has already verified against a configured client's
/// key ever reaches the cache, so this bounds what an ADMITTED client can make
/// the broker remember, not what a stranger can. At two generations of two
/// windows each that is a sustained rate far above anything a broker proxying
/// every call to an upstream MCP server reaches, and going over it refuses
/// rather than forgetting: see [`tokenfuse_dpop::ReplayCache`].
const REPLAY_CAP: usize = 16_384;

/// What the door decided about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Neither door is configured, so the broker authenticates nobody, exactly
    /// as it has since it existed. A loopback deployment that sets none of this
    /// is byte-for-byte unchanged.
    Open,
    /// A `TOKENFUSE_MCP_KEYS` credential resolved to this `key_id`.
    Bearer(String),
    /// A proof of possession resolved to this CIMD `client_id`.
    Proof(String),
    Refused(DoorRefusal),
}

/// Why a call was turned away.
///
/// The wire never distinguishes these: every one of them is the same 401, for
/// the reason `tokenfuse_dpop::ProofRefusal` documents. They exist so the
/// operator's own log says which door and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoorRefusal {
    /// Nothing was presented that a configured door could judge.
    NoCredential,
    /// A bearer secret was presented and resolves to nothing.
    UnknownCredential,
    /// A proof was presented and did not verify.
    BadProof,
    /// A proof verified, and no configured client published the key that signed
    /// it. The identity comes from the key, so this names nobody.
    UnknownClient,
    /// That `jti` has been used already inside the window.
    Replayed,
    /// The replay cache is full, so single use can no longer be promised. It
    /// refuses rather than forgetting, which would be the guard quietly ceasing
    /// to guard at exactly the moment somebody is pushing on it.
    ReplayCacheFull,
}

/// The two doors and the switch between them, borrowed for one decision.
pub struct Door<'a> {
    pub keys: &'a ClientKeys,
    pub clients: &'a ClientRegistry,
    /// `TOKENFUSE_MCP_REQUIRE_PROOF`: a bearer credential alone is no longer
    /// enough. The way OUT of the migration state below.
    pub require_proof: bool,
}

/// Decide whether this request may be served, from what it presented.
///
/// A pure function over the request's credentials, so the decision is testable
/// without a listener, an upstream or a vault, the same property
/// [`crate::mcpbroker::refuse_open_bind`] was written for.
///
/// # The composition rule, which is the part worth reading
///
/// **A caller that presents a proof is judged by it, and a broken proof is a
/// refusal, never a fall-back to the weaker door** even when the same call also
/// carries a good bearer credential. Anything else means an attacker who has
/// stolen an `x-fuse-key` can strip the DPoP header, or send a broken one, and
/// be back in the old world. This is `delegation.rs`'s own rule one plane over:
/// a bound credential honoured with the binding skipped is a failure that looks
/// exactly like it is working.
///
/// **A caller that presents NO proof falls through to the bearer door while one
/// is configured.** That is the migration state, it is how an operator adds the
/// first CIMD client without breaking every existing one, and it is not silent:
/// [`crate::mcpbroker::bearer_door_still_open_warning`] says so at startup and
/// `require_proof` is the way to end it.
pub fn admit(
    door: Door<'_>,
    presented_key: Option<&str>,
    proof: Option<&str>,
    path: &str,
    now: i64,
) -> Admission {
    let proof = proof.map(str::trim).filter(|p| !p.is_empty());

    if door.clients.enabled() {
        if let Some(p) = proof {
            return match door.clients.authenticate(p, path, now) {
                Ok(client_id) => Admission::Proof(client_id.to_string()),
                Err(why) => Admission::Refused(why),
            };
        }
        if door.require_proof || !door.keys.enabled() {
            return Admission::Refused(DoorRefusal::NoCredential);
        }
        // Otherwise fall through to the bearer door: the migration state.
    } else if door.require_proof {
        // A started process cannot be here: `refuse_proof_with_no_clients`
        // refuses this combination at startup, because it is a door nothing can
        // ever open. Answered closed anyway, since a direct caller of `admit` is
        // not a started process and a permissive answer here would be a
        // surprising way to get one.
        return Admission::Refused(DoorRefusal::NoCredential);
    }

    if !door.keys.enabled() {
        return Admission::Open;
    }
    match door.keys.resolve(presented_key.unwrap_or_default().trim()) {
        Some(key_id) => Admission::Bearer(key_id.to_string()),
        None => Admission::Refused(DoorRefusal::UnknownCredential),
    }
}

/// A `TOKENFUSE_MCP_CLIENT_IDS` (or `TOKENFUSE_MCP_PROOF_URL`) value that was
/// set and cannot be used. Startup refuses on this rather than falling back to
/// "no clients configured", because that fallback leaves the door in whatever
/// state the OTHER variable happens to be in, at the moment an operator
/// believed they had just tightened it. Same conclusion
/// [`crate::clientkeys::EmptySpec`] and `TOKENFUSE_MCP_SECRET_SCOPES` both
/// reached.
#[derive(Debug, PartialEq, Eq)]
pub struct ClientSpecError(String);

impl std::fmt::Display for ClientSpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TOKENFUSE_MCP_CLIENT_IDS is set and cannot be used: {}. Expected a JSON array of \
             client metadata documents (or a path to a file holding one), each with an https \
             `client_id` and a `jwks` this broker can verify against; refusing to start rather \
             than run the credential-broker with the proof door silently off.",
            self.0
        )
    }
}

impl std::error::Error for ClientSpecError {}

/// The CIMD clients this broker will admit, keyed by the RFC 7638 thumbprint of
/// each published key.
///
/// **Keyed by the key, not by anything the caller says about itself.** A caller
/// does not name which client it is; the key that signed its proof does. That is
/// CLAUDE.md invariant 15's rule one door over: anything a caller can choose, a
/// caller can change, so an identity read off a header is an identity an
/// attacker picks. It also removes a whole failure class, the call that claims
/// client A and signs with client B's key, by making it unrepresentable.
pub struct ClientRegistry {
    /// thumbprint -> `client_id`.
    by_jkt: HashMap<String, String>,
    /// The origin clients address this broker at (`https://mcp.acme.example`),
    /// with any trailing slash removed. Server-side and operator-supplied on
    /// purpose: reconstructing it from a `Host` header would let the caller make
    /// `htu` agree with anything it liked, which turns the check into decoration.
    origin: String,
    replay: ReplayCache,
}

impl Default for ClientRegistry {
    fn default() -> Self {
        ClientRegistry {
            by_jkt: HashMap::new(),
            origin: String::new(),
            replay: ReplayCache::new(REPLAY_CAP),
        }
    }
}

impl ClientRegistry {
    /// Build the allowlist from `TOKENFUSE_MCP_CLIENT_IDS` and
    /// `TOKENFUSE_MCP_PROOF_URL`.
    ///
    /// `spec` is either the JSON itself or a path to a file holding it, the same
    /// inline-or-path shape `TOKENFUSE_CLOUD_OIDC_JWKS` uses: a set of JWKS is
    /// too large to want in an environment variable and too security-relevant to
    /// fetch at run time.
    ///
    /// Blank is "not configured" and yields a disabled registry. Anything else
    /// that cannot be turned into at least one usable client is an error.
    pub fn from_spec(spec: &str, origin: &str) -> Result<Self, ClientSpecError> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Ok(Self::default());
        }
        let origin = origin.trim().trim_end_matches('/');
        if origin.is_empty() {
            return Err(ClientSpecError(
                "no TOKENFUSE_MCP_PROOF_URL is set, so a proof could not be checked against the \
                 address clients actually call. Set it to the origin they address this broker at, \
                 for example https://mcp.acme.example"
                    .into(),
            ));
        }

        let text = if trimmed.starts_with('[') || trimmed.starts_with('{') {
            trimmed.to_string()
        } else {
            std::fs::read_to_string(trimmed)
                .map_err(|e| ClientSpecError(format!("{trimmed}: {e}")))?
        };
        let parsed: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| ClientSpecError(format!("not JSON this broker can read: {e}")))?;
        let documents = parsed
            .as_array()
            .ok_or_else(|| ClientSpecError("expected a JSON array of documents".into()))?;
        if documents.is_empty() {
            return Err(ClientSpecError(
                "the array is empty, so no client would ever be admitted".into(),
            ));
        }

        let mut by_jkt = HashMap::new();
        let mut seen_ids = HashSet::new();
        for doc in documents {
            let client_id = doc
                .get("client_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .trim();
            if !is_https_url(client_id) {
                return Err(ClientSpecError(format!(
                    "client_id {client_id:?} is not an absolute https URL, which is what CIMD \
                     makes a client id"
                )));
            }
            if !seen_ids.insert(client_id.to_string()) {
                return Err(ClientSpecError(format!(
                    "client_id {client_id:?} appears more than once"
                )));
            }
            let keys = doc
                .get("jwks")
                .and_then(|j| j.get("keys"))
                .and_then(|k| k.as_array())
                .filter(|k| !k.is_empty())
                .ok_or_else(|| {
                    ClientSpecError(format!(
                        "client {client_id:?} publishes no `jwks.keys`, so nothing it sends could \
                         ever be verified"
                    ))
                })?;
            for key in keys {
                // A key this broker cannot verify against is refused rather than
                // skipped. Skipping it would leave the operator believing they
                // published something that is honoured, and the difference only
                // shows up as a client that mysteriously cannot get in.
                let jkt = thumbprint_of_json(key).map_err(|e| {
                    ClientSpecError(match e {
                        KeyRefusal::Malformed => {
                            format!("client {client_id:?} published something that is not a JWK")
                        }
                        KeyRefusal::Unsupported => format!(
                            "client {client_id:?} published a key of a type this broker cannot \
                             verify against (only RSA and EC)"
                        ),
                    })
                })?;
                // The identity is derived from the key, so one key belonging to
                // two clients would make it ambiguous. Refused here, where it is
                // one error message an operator reads, rather than at request
                // time, where it would be a coin toss.
                if let Some(other) = by_jkt.insert(jkt, client_id.to_string()) {
                    if other != client_id {
                        return Err(ClientSpecError(format!(
                            "clients {other:?} and {client_id:?} publish the same key, so a proof \
                             signed with it would name neither"
                        )));
                    }
                }
            }
        }

        Ok(ClientRegistry {
            by_jkt,
            origin: origin.to_string(),
            replay: ReplayCache::new(REPLAY_CAP),
        })
    }

    /// Whether the proof door is on at all.
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.by_jkt.is_empty()
    }

    /// How many clients are configured (startup logging).
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_jkt.values().collect::<HashSet<_>>().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_jkt.is_empty()
    }

    /// The `client_id` this proof belongs to, or why it does not.
    ///
    /// The order is deliberate and is the difference between a replay cache and
    /// a memory-growth vector: the proof is verified in full, and the key is
    /// looked up, BEFORE anything is recorded. So only a caller already holding
    /// a configured client's private key can make this broker remember
    /// anything, which is what makes refusing at the cap a self-inflicted wound
    /// rather than something a stranger can do to a deployment.
    pub fn authenticate(&self, proof: &str, path: &str, now: i64) -> Result<&str, DoorRefusal> {
        let expected = format!("{}{}", self.origin, path);
        // POST because that is the only method this door ever sees: `mcpbroker::app`
        // routes `/` and `/mcp` with `post` and nothing else.
        let verified =
            verify_proof(proof, "POST", &expected, now).map_err(|_| DoorRefusal::BadProof)?;
        let client_id = self
            .by_jkt
            .get(&verified.jkt)
            .ok_or(DoorRefusal::UnknownClient)?;
        match self.replay.check_and_record(&verified.jti, now) {
            Ok(()) => Ok(client_id),
            Err(ReplayRefusal::Seen) => Err(DoorRefusal::Replayed),
            Err(ReplayRefusal::Full) => Err(DoorRefusal::ReplayCacheFull),
        }
    }
}

/// Whether `s` is an absolute https URL with a host.
///
/// Written out rather than pulled in, because the whole question is four
/// conditions and adding a URL parser to the gateway to ask them would be a
/// dependency carried by every request this binary serves.
fn is_https_url(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("https://") else {
        return false;
    };
    if s.chars().any(char::is_whitespace) {
        return false;
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    !host.is_empty()
}
