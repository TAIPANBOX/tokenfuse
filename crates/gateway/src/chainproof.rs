//! Turning a delegation token into a chain the PDP may believe.
//!
//! # What was wrong before this file
//!
//! Wardryx gained `deny_if_chain_unproven`, `max_chain_depth` and
//! `require_root_principal`, and this gateway sent it a chain taken from the
//! `x-fuse-on-behalf-of` header. So a depth cap of three capped a number the
//! CALLER chose, and `deny_if_chain_unproven` denied on the strength of a
//! claim. vouchryx issues a token that settles the question and two languages
//! can verify one; until this file, no request path called either.
//!
//! # One place, because there are two doors
//!
//! The MCP broker and the LLM proxy both build a `DecideContext`, and both took
//! the chain from the same header. A rule written twice is a rule that will be
//! two rules, which is most of what went wrong in this estate this week. The
//! composition rule lives here and both doors call it.
//!
//! # The rule
//!
//! - **No token: nothing changes.** The header chain is forwarded exactly as
//!   before and `chain_proven` is false. That is what makes this additive: a
//!   deployment that configures nothing is byte for byte what it was, and the
//!   PDP now hears "nobody proved this" instead of hearing nothing.
//! - **A token that verifies wins.** `on_behalf_of` comes from the token, not
//!   from the header, and `chain_proven` is true.
//! - **A token that does not verify is a refusal, never a fall-back.** This is
//!   `mcpdoor`'s rule one field over: a credential honoured with its binding
//!   skipped is a failure that looks exactly like it is working.
//! - **A token plus a header that says something else is a refusal.** Not a
//!   silent preference for the verified one. A caller sending both is either
//!   confused or probing which one this code believes, and answering that
//!   question quietly is how a downgrade hides. It is compared as a SET as
//!   well as in order, so neither a reordering nor an extra name passes.
//!
//! # What this does NOT do
//!
//! It does not check that the chain is ordered root-first: that is a property
//! of how the issuer BUILT the list and cannot be read off the finished one,
//! which `tokenfuse_delegation::VerifiedDelegation::chain` says in its own
//! words. It does not authorize anything; it hands the PDP a fact and the PDP
//! decides. And it says nothing about the upstream leg: nothing is signed on
//! the way out.

use std::sync::Arc;

use tokenfuse_delegation::{verify_delegation, DelegationConfig, Refusal};

/// The most entries a declared chain may carry: agent-passport SPEC 5.1's
/// "Maximum chain depth is 32 entries", read from the delegation crate rather
/// than retyped, so the header cap and the token cap are one number.
///
/// SPEC 5.1 states the bound on the chain ITSELF; proving a chain (5.2) is
/// optional and additive. The v0.2 envelope pins `maxItems: 32` on
/// `on_behalf_of` and `agent-conform` runs the record's validator on every
/// line, so a chain longer than this is one no consumer will hold, whether or
/// not anybody verified it. Measured 2026-09-17 with no issuer configured
/// (tokenfuse#297): forty entries were forwarded, answered 200, and every
/// event of that request would have carried a chain the record refuses.
pub const MAX_CHAIN_ENTRIES: usize = tokenfuse_delegation::MAX_CHAIN_ENTRIES;

/// A declared chain longer than [`MAX_CHAIN_ENTRIES`]: refused on parse, at
/// both doors, before anything is resolved, reserved or forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainOverCap {
    /// How many entries the header carried.
    pub entries: usize,
}

/// Split the raw `x-fuse-on-behalf-of` value into the ordered, root-first
/// chain (agent-passport SPEC 5: comma-separated, entries trimmed, empty
/// entries dropped), and refuse one longer than the cap.
///
/// Entries are still opaque strings here: the acyclic rule and the
/// `agent://`/`user://` scheme rule are applied to a TOKEN's chain by the
/// delegation crate and are not applied to a declared chain by this
/// function. That is a stated limit, not an oversight: the cap is what the
/// 2026-09-17 run measured as missing, and widening the parse is a separate
/// decision. An absent header is an empty chain, SPEC 5's "acts
/// autonomously".
pub fn declared_chain(raw: Option<&str>) -> Result<Vec<String>, ChainOverCap> {
    let chain: Vec<String> = raw
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if chain.len() > MAX_CHAIN_ENTRIES {
        return Err(ChainOverCap {
            entries: chain.len(),
        });
    }
    Ok(chain)
}

/// The verifier plus what the operator configured, or nothing at all.
///
/// Absent is the default and the common case. `Option<Arc<..>>` rather than a
/// bool plus fields, so "off" cannot be represented as "on with empty config",
/// which is the shape that silently trusts every token.
pub struct Proving {
    pub cfg: DelegationConfig,
    /// The absolute origin this gateway is reached at, no path: what a proof's
    /// `htu` is compared against once the door has appended its own route.
    ///
    /// The ORIGIN is configured and the PATH is not, because the path is a
    /// fact the code knows and the origin is a fact only the deployment knows.
    /// A gateway behind a proxy cannot read its own external origin off the
    /// request, and letting it try is how `htu` ends up agreeing with anything.
    pub origin: String,
}

pub type ChainProof = Option<Arc<Proving>>;

/// What one request's credentials resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chain {
    /// Nobody proved anything. The header chain stands, as a claim.
    Claimed(Vec<String>),
    /// A token verified, and this is what it said, plus what proved it.
    ///
    /// The proof travels with the chain rather than beside it, because a chain
    /// that arrives without its proof cannot be told apart from one nobody
    /// proved. SPEC 5.2 reads an absent proof as NOT proven, so the two must
    /// not be separable by a call site that forgets one of them.
    Proven {
        chain: Vec<String>,
        proof: tokenfuse_core::agent_event::DelegationProof,
    },
    /// Refused, and the wire must not distinguish these from each other.
    Refused(ChainRefusal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainRefusal {
    /// A token was presented and did not verify.
    BadToken,
    /// A token verified and the caller also declared a different chain.
    Contradicted,
}

/// Read a `DPoP`-scheme credential out of an `Authorization` header.
///
/// RFC 9449's own scheme, so a token bound to a key is presented as one rather
/// than as a bearer credential that happens to have a `cnf` claim. A `Bearer`
/// value is deliberately NOT read here: this gateway's bearer credential is
/// `x-fuse-key`, and quietly accepting a delegation token in the bearer slot
/// would be the same door twice under two names.
pub fn dpop_credential(authorization: Option<&str>) -> Option<&str> {
    let v = authorization?.trim();
    let rest = v
        .strip_prefix("DPoP ")
        .or_else(|| v.strip_prefix("dpop "))?;
    let rest = rest.trim();
    (!rest.is_empty()).then_some(rest)
}

/// Resolve one request's chain. See the module docs for the rule.
#[allow(clippy::too_many_arguments)]
pub fn resolve(
    cfg: &ChainProof,
    token: Option<&str>,
    proof: Option<&str>,
    method: &str,
    url: &str,
    declared: &[String],
    now: i64,
    revoked: impl Fn(&str, &str, i64) -> bool,
) -> Chain {
    let (Some(proving), Some(token)) = (cfg.as_ref(), token) else {
        // Either the operator configured no issuer, or the caller presented no
        // token. Both mean the same thing to the PDP and neither is an error:
        // a chain nobody proved is still a chain somebody wants acted on.
        return Chain::Claimed(declared.to_vec());
    };

    let url = format!("{}{}", proving.origin.trim_end_matches('/'), url);
    let verified = match verify_delegation(&proving.cfg, token, proof, method, &url, now, revoked) {
        Ok(v) => v,
        // Every refusal is the same answer on the wire, for the reason
        // `mcpdoor::DoorRefusal` gives: which of them it was is an oracle a
        // caller must not be handed. Matched exhaustively rather than with a
        // wildcard, so a variant added to `Refusal` later fails to compile here
        // instead of silently joining this arm.
        Err(
            Refusal::Malformed
            | Refusal::BadSignature
            | Refusal::Issuer
            | Refusal::Audience
            | Refusal::Expired
            | Refusal::NotBound
            | Refusal::NoProof
            | Refusal::WrongKey
            | Refusal::Revoked,
        ) => return Chain::Refused(ChainRefusal::BadToken),
    };

    if !declared.is_empty() && !same_chain(declared, &verified.chain) {
        return Chain::Refused(ChainRefusal::Contradicted);
    }
    // `iss` comes from the CONFIG rather than from the token, because
    // `verify_delegation` matched the token's `iss` against it exactly. Reading
    // it back off the token would record what the token claimed; reading it off
    // the config records what this deployment verified against.
    let proof = tokenfuse_core::agent_event::DelegationProof {
        jti: verified.jti,
        jkt: verified.jkt,
        iss: proving.cfg.issuer.clone(),
        exp: verified.expires_at,
    };
    Chain::Proven {
        chain: verified.chain,
        proof,
    }
}

/// The agent a PROVEN chain names as its current actor, if it names one.
///
/// # Why a proven chain may stand in for a header, and a claimed one may not
///
/// The record's `agent_id` came from `x-fuse-agent-id`, a header the caller
/// writes. Measured 2026-08-26 on a running gateway: a request carrying a
/// DPoP-bound, issuer-signed chain raised two `taint_raised` events in enforce
/// mode and BOTH were dropped, because that header was absent. An attack was
/// detected on the request with the strongest identity this gateway ever sees,
/// and the security record was empty.
///
/// A claimed chain must never do this. It is the same free-form weakness with
/// extra steps: a caller who can write the header can write the chain.
///
/// # The last element, and only when it is an agent
///
/// `chain_of` builds `[sub] + reverse(act)`, and RFC 8693 nests `act`
/// current-first, so after the reverse the current actor is LAST. The first
/// element is the root, usually a human.
///
/// A token with no `act` at all is the trap: the chain is then `[sub]` alone,
/// and `sub` may be `user://...`, a person calling directly with no agent
/// anywhere. Taking the last element unconditionally would put a natural person
/// into `agent_id`, which this estate refuses by name.
///
/// The check is the SCHEME and deliberately not the full grammar. An
/// off-grammar leaf like `agent://Acme/Bot` is still the proven actor, and this
/// repository's rule is to write, count and report a nonconforming id rather
/// than empty the log. A `user://` or `claimed:` leaf is different in kind, and
/// is never a fallback.
pub fn proven_actor(chain: &Chain) -> Option<&str> {
    let Chain::Proven { chain, .. } = chain else {
        return None;
    };
    chain.last().map(|leaf| leaf.trim()).filter(|leaf| {
        // The scheme AND something after it. `starts_with("agent://")`
        // alone accepts the bare scheme, which is not an identity and would
        // put `agent://` in the subject of a security record.
        leaf.strip_prefix("agent://")
            .is_some_and(|rest| !rest.is_empty())
    })
}

/// Order AND membership. Compared both ways on purpose: an equal-length
/// reordering has the same set, and an extra name has the same prefix, so
/// either comparison alone lets one of the two through.
fn same_chain(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() || a != b {
        return false;
    }
    let mut x: Vec<&String> = a.iter().collect();
    let mut y: Vec<&String> = b.iter().collect();
    x.sort();
    y.sort();
    x == y
}

/// Build the verifier from the environment, or `None` when no issuer is named.
///
/// Three variables, all required together, because two of the three is not a
/// weaker configuration but an ambiguous one:
///
/// - `TOKENFUSE_DELEGATION_JWKS`: a FILE holding the issuer's JWKS.
/// - `TOKENFUSE_DELEGATION_ISSUER`: the exact `iss`. Not a prefix; a prefix is
///   how a service ends up trusting `vouchryx.acme.example.evil.test`.
/// - `TOKENFUSE_DELEGATION_AUDIENCE`: the `aud` this deployment answers to.
///   May be empty, which accepts any and is a real choice for a single-tenant
///   deployment. Empty is therefore distinct from unset.
///
/// A file rather than a URL, and read once at startup, for the reason
/// `TOKENFUSE_CLOUD_OIDC_JWKS` gives and `mcpdoor` repeats: a fetch on the
/// request path makes this gateway's availability somebody else's website, and
/// a fetch at startup buys one deploy step while costing a boot-time dependency
/// on a third party. The operator's own deploy fetches it.
///
/// # It aborts rather than starting without what it was told to use
///
/// A misspelt path or a JWKS that does not parse means the operator asked for
/// verification and would silently get none, which is the failure that looks
/// exactly like it is working. Same choice, and the same exit code, as
/// `firewall::from_env` on a bad policy file.
pub fn from_env() -> ChainProof {
    let issuer = std::env::var("TOKENFUSE_DELEGATION_ISSUER").unwrap_or_default();
    let jwks_path = std::env::var("TOKENFUSE_DELEGATION_JWKS").unwrap_or_default();
    if issuer.trim().is_empty() && jwks_path.trim().is_empty() {
        return None;
    }
    if issuer.trim().is_empty() || jwks_path.trim().is_empty() {
        eprintln!(
            "tokenfuse: TOKENFUSE_DELEGATION_ISSUER and TOKENFUSE_DELEGATION_JWKS must be \
             set together. One without the other cannot verify anything, and starting \
             anyway would mean every delegation token is refused while the log says the \
             door is on."
        );
        std::process::exit(2);
    }
    let raw = match std::fs::read_to_string(&jwks_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tokenfuse: TOKENFUSE_DELEGATION_JWKS ({jwks_path}): {e}");
            std::process::exit(2);
        }
    };
    let jwks = match tokenfuse_delegation::parse_jwks(&raw) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("tokenfuse: TOKENFUSE_DELEGATION_JWKS ({jwks_path}) is not a JWKS: {e}");
            std::process::exit(2);
        }
    };
    if jwks.keys.is_empty() {
        eprintln!(
            "tokenfuse: TOKENFUSE_DELEGATION_JWKS ({jwks_path}) holds no keys, so every \
             token would be refused by a door reporting itself as on."
        );
        std::process::exit(2);
    }
    let origin = std::env::var("TOKENFUSE_DELEGATION_URL").unwrap_or_default();
    if origin.trim().is_empty() {
        eprintln!(
            "tokenfuse: TOKENFUSE_DELEGATION_URL must name the absolute origin this \
             gateway is reached at, so a proof's `htu` has something to be compared \
             against. Without it the binding to one request is decoration."
        );
        std::process::exit(2);
    }
    Some(Arc::new(Proving {
        cfg: DelegationConfig {
            jwks,
            issuer,
            audience: std::env::var("TOKENFUSE_DELEGATION_AUDIENCE").unwrap_or_default(),
        },
        origin,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The number is written out here independently of the constant it
    /// checks (invariant 14's lesson: an expectation taken from the thing
    /// under test cannot fail), and it is the delegation crate's number, so a
    /// token's chain and a declared chain are bounded by one rule.
    #[test]
    fn the_header_cap_is_the_delegation_crates_cap_and_not_a_second_number() {
        assert_eq!(MAX_CHAIN_ENTRIES, 32, "agent-passport SPEC 5.1's number");
        assert_eq!(MAX_CHAIN_ENTRIES, tokenfuse_delegation::MAX_CHAIN_ENTRIES);

        let entries = |n: usize| {
            (0..n)
                .map(|i| format!("agent://acme.example/hop{i}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        let at_cap =
            declared_chain(Some(&entries(32))).expect("32 entries is the cap, not over it");
        assert_eq!(at_cap.len(), 32);
        assert_eq!(
            at_cap[0], "agent://acme.example/hop0",
            "root first, unchanged"
        );
        assert_eq!(
            declared_chain(Some(&entries(33))),
            Err(ChainOverCap { entries: 33 }),
            "one past the cap is refused and says how many were sent"
        );
        assert_eq!(
            declared_chain(Some(&entries(40))),
            Err(ChainOverCap { entries: 40 }),
            "the measured case"
        );
    }

    /// The parse itself: trimmed, empties dropped, an absent header an empty
    /// chain. Pinned because both doors now read through this one function
    /// and each used to have its own splitter.
    #[test]
    fn a_declared_chain_is_split_trimmed_and_absent_is_empty() {
        assert_eq!(declared_chain(None), Ok(Vec::new()));
        assert_eq!(declared_chain(Some("")), Ok(Vec::new()));
        assert_eq!(declared_chain(Some(" , ,")), Ok(Vec::new()));
        assert_eq!(
            declared_chain(Some(" user://acme/alice , agent://acme/triage,, ")),
            Ok(vec![
                "user://acme/alice".to_string(),
                "agent://acme/triage".to_string()
            ])
        );
        // Empty entries do not count towards the cap: the cap is on entries
        // the chain carries, and a stray comma carries none.
        let padded = format!("{},", ",".repeat(40));
        assert_eq!(declared_chain(Some(&padded)), Ok(Vec::new()));
    }

    #[test]
    fn a_dpop_credential_is_read_and_a_bearer_one_is_not() {
        assert_eq!(
            dpop_credential(Some("DPoP abc.def.ghi")),
            Some("abc.def.ghi")
        );
        assert_eq!(dpop_credential(Some("dpop abc")), Some("abc"));
        assert_eq!(dpop_credential(Some("Bearer abc.def.ghi")), None);
        assert_eq!(dpop_credential(Some("DPoP   ")), None);
        assert_eq!(dpop_credential(None), None);
    }

    #[test]
    fn with_nothing_configured_the_declared_chain_stands_as_a_claim() {
        let declared = vec!["user://a".to_string(), "agent://b".to_string()];
        let got = resolve(
            &None,
            Some("t"),
            None,
            "POST",
            "/v1/messages",
            &declared,
            0,
            |_, _, _| false,
        );
        assert_eq!(got, Chain::Claimed(declared));
    }

    #[test]
    fn chains_are_compared_by_order_and_by_membership() {
        let a = vec!["user://a".to_string(), "agent://b".to_string()];
        assert!(same_chain(&a, &a));
        // a reordering has the same set
        assert!(!same_chain(
            &a,
            &["agent://b".to_string(), "user://a".to_string()]
        ));
        // an extra name has the same prefix
        assert!(!same_chain(
            &a,
            &[
                "user://a".to_string(),
                "agent://b".to_string(),
                "agent://c".to_string()
            ]
        ));
    }

    /// SPEC 5.2 in one test: the proof travels with the chain, it names the
    /// token that proved it, and its `iss` is the one this deployment VERIFIED
    /// against rather than the one the token claimed.
    ///
    /// Red before `Chain::Proven` grew the proof: the variant carried a bare
    /// `Vec<String>` and the four values `verify_delegation` had just checked
    /// were dropped on the floor, so no record could ever say a chain had been
    /// proven at all.
    #[test]
    fn a_proven_chain_carries_what_proved_it() {
        use tokenfuse_delegation::testing::{cfg, proof_at, token, Key};
        let (issuer, holder) = (Key::new(), Key::new());
        let now = 1_800_000_000;
        let origin = "https://tokenfuse.acme.example";
        let cfg = cfg(&issuer);
        let issuer_configured = cfg.issuer.clone();
        let proving: ChainProof = Some(Arc::new(Proving {
            cfg,
            origin: origin.to_string(),
        }));
        let tok = token(
            &issuer,
            &holder,
            now,
            serde_json::json!({
                "sub": "user://acme/alice",
                "act": {"sub": "agent://acme/triage"},
                "jti": "tok-live-1",
                "exp": now + 300
            }),
        );
        let dpop = proof_at(
            &holder,
            now,
            "POST",
            &format!("{origin}/v1/messages"),
            "p-1",
        );

        let resolved = resolve(
            &proving,
            Some(&tok),
            Some(&dpop),
            "POST",
            "/v1/messages",
            &[],
            now,
            |_, _, _| false,
        );

        let Chain::Proven { chain, proof } = resolved else {
            panic!("a good token did not resolve as proven: {resolved:?}");
        };
        assert_eq!(chain, vec!["user://acme/alice", "agent://acme/triage"]);
        assert_eq!(proof.jti, "tok-live-1", "an auditor cannot find the token");
        assert_eq!(proof.exp, now + 300, "the proof carries no freshness");
        assert!(!proof.jkt.is_empty(), "who was holding it is unrecorded");
        assert_eq!(
            proof.iss, issuer_configured,
            "the issuer on the record must be the one this deployment verified \
             against, not the one the token claimed to be from"
        );
    }

    /// The other half, and the one that keeps the first honest: a chain nobody
    /// proved carries nothing to say it was proven. SPEC 5.2 reads an absent
    /// proof as NOT proven, so this is what stops a claim reading as a proof.
    #[test]
    fn a_claimed_chain_carries_no_proof() {
        let declared = vec![
            "user://acme/alice".to_string(),
            "agent://acme/triage".to_string(),
        ];
        let resolved = resolve(
            &None,
            Some("a.token.nobody.configured.an.issuer.for"),
            None,
            "POST",
            "/v1/messages",
            &declared,
            1_800_000_000,
            |_, _, _| false,
        );
        assert_eq!(resolved, Chain::Claimed(declared));
    }

    /// The measured defect, as a unit: a proven chain names its actor, so a
    /// record has something to be filed under even with no header.
    #[test]
    fn a_proven_chain_names_the_agent_that_acted() {
        let proven = Chain::Proven {
            chain: vec![
                "user://acme/alice".to_string(),
                "agent://acme/triage".to_string(),
            ],
            proof: tokenfuse_core::agent_event::DelegationProof {
                jti: "t".into(),
                jkt: "k".into(),
                iss: "https://vouchryx.acme.example".into(),
                exp: 0,
            },
        };
        assert_eq!(proven_actor(&proven), Some("agent://acme/triage"));
    }

    /// The test that pins the whole design. If anybody ever widens the fallback
    /// to claimed chains, this goes red, and it should: a caller who can write
    /// the header can write the chain.
    #[test]
    fn a_claimed_chain_names_nobody() {
        let claimed = Chain::Claimed(vec![
            "user://acme/alice".to_string(),
            "agent://acme/triage".to_string(),
        ]);
        assert_eq!(proven_actor(&claimed), None);
        assert_eq!(proven_actor(&Chain::Refused(ChainRefusal::BadToken)), None);
    }

    /// A token with no `act` is a person calling directly. The last element is
    /// then the human, and a human is not an agent id.
    #[test]
    fn a_chain_with_no_agent_in_it_names_nobody() {
        for leaf in ["user://acme/alice", "claimed:agent://acme/triage"] {
            let proven = Chain::Proven {
                chain: vec![leaf.to_string()],
                proof: tokenfuse_core::agent_event::DelegationProof {
                    jti: "t".into(),
                    jkt: "k".into(),
                    iss: "i".into(),
                    exp: 0,
                },
            };
            assert_eq!(proven_actor(&proven), None, "{leaf} was taken as an agent");
        }
    }

    /// An off-grammar leaf is still the actor the issuer named. Written and
    /// counted rather than dropped, which is this repository's rule for a
    /// nonconforming id and is why the check is the scheme and not the grammar.
    #[test]
    fn an_off_grammar_agent_is_still_the_actor() {
        let proven = Chain::Proven {
            chain: vec!["agent://Acme/Bot".to_string()],
            proof: tokenfuse_core::agent_event::DelegationProof {
                jti: "t".into(),
                jkt: "k".into(),
                iss: "i".into(),
                exp: 0,
            },
        };
        assert_eq!(proven_actor(&proven), Some("agent://Acme/Bot"));
    }

    /// The bare scheme is not an identity. `starts_with` alone accepted it and
    /// would have put `agent://` in the subject of a security record.
    #[test]
    fn the_bare_scheme_is_not_an_agent() {
        for leaf in ["agent://", "agent:// ", "  "] {
            let proven = Chain::Proven {
                chain: vec![leaf.to_string()],
                proof: tokenfuse_core::agent_event::DelegationProof {
                    jti: "t".into(),
                    jkt: "k".into(),
                    iss: "i".into(),
                    exp: 0,
                },
            };
            assert_eq!(
                proven_actor(&proven),
                None,
                "{leaf:?} was taken as an agent"
            );
        }
    }
}
