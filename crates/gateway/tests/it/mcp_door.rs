//! The MCP credential-broker's door, when the credential is a KEY rather than a
//! shared secret: CIMD client ids (draft-ietf-oauth-client-id-metadata-document)
//! and RFC 9449 proof of possession.
//!
//! These sit in an integration test rather than beside the code because the
//! whole point of `mcpdoor::admit` is that it is a pure function over what a
//! request presented: it needs no listener, no state machine and no upstream, so
//! it can be driven from outside the crate exactly as an operator's client would
//! drive it.

use base64::Engine as _;
use p256::ecdsa::signature::Signer;
use tokenfuse_gateway::clientkeys::ClientKeys;
use tokenfuse_gateway::mcpdoor::{admit, Admission, ClientRegistry, Door, DoorRefusal};

const ORIGIN: &str = "https://mcp.acme.example";
const PATH: &str = "/mcp";
const CLIENT: &str = "https://release-bot.acme.example/mcp-client.json";
const NOW: i64 = 1_800_000_000;

// --- a client that publishes a key, and signs proofs with it ----------------

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

struct Key {
    signing: p256::ecdsa::SigningKey,
}

impl Key {
    fn new() -> Self {
        Key {
            signing: p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng),
        }
    }

    fn jwk(&self) -> serde_json::Value {
        let point = self.signing.verifying_key().to_encoded_point(false);
        serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": b64(point.x().unwrap()), "y": b64(point.y().unwrap()),
        })
    }

    fn sign(&self, header: serde_json::Value, claims: serde_json::Value) -> String {
        let signing = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        let sig: p256::ecdsa::Signature = self.signing.sign(signing.as_bytes());
        format!("{signing}.{}", b64(&sig.to_bytes()))
    }

    /// An RFC 9449 proof for `POST {ORIGIN}{path}` at `iat`.
    fn proof(&self, path: &str, iat: i64, jti: &str) -> String {
        self.sign(
            serde_json::json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk()}),
            serde_json::json!({"htm": "POST", "htu": format!("{ORIGIN}{path}"), "iat": iat, "jti": jti}),
        )
    }
}

/// The client metadata document a CIMD client publishes at its own client_id
/// URL. This is what an operator's deploy step fetches; the broker never
/// dereferences a URL itself.
fn document(client_id: &str, key: &Key) -> serde_json::Value {
    serde_json::json!({
        "client_id": client_id,
        "client_name": "release-bot",
        "jwks": {"keys": [key.jwk()]},
    })
}

fn registry(docs: serde_json::Value) -> ClientRegistry {
    ClientRegistry::from_spec(&docs.to_string(), ORIGIN).expect("a usable client spec")
}

fn one_client(key: &Key) -> ClientRegistry {
    registry(serde_json::json!([document(CLIENT, key)]))
}

fn keys(spec: &str) -> ClientKeys {
    ClientKeys::from_spec(spec).expect("a usable key spec")
}

fn door<'a>(k: &'a ClientKeys, c: &'a ClientRegistry, require_proof: bool) -> Door<'a> {
    Door {
        keys: k,
        clients: c,
        require_proof,
    }
}

// --- the default nobody asked to change -------------------------------------

/// The broker has authenticated nobody since it existed, and a loopback
/// deployment that configures neither door must stay byte-for-byte that.
#[test]
fn a_broker_with_neither_door_configured_admits_everyone_exactly_as_before() {
    let (k, c) = (keys(""), ClientRegistry::default());
    assert!(matches!(
        admit(door(&k, &c, false), None, None, PATH, NOW),
        Admission::Open
    ));
}

#[test]
fn a_bearer_key_still_opens_a_door_that_has_only_bearer_keys() {
    let (k, c) = (keys("sk-broker-abc:tool-user"), ClientRegistry::default());
    match admit(door(&k, &c, false), Some("sk-broker-abc"), None, PATH, NOW) {
        Admission::Bearer(key_id) => assert_eq!(key_id, "tool-user"),
        other => panic!("a known bearer credential must still be admitted: {other:?}"),
    }
    assert!(matches!(
        admit(door(&k, &c, false), Some("wrong"), None, PATH, NOW),
        Admission::Refused(_)
    ));
}

/// A proof means nothing to a broker that was never given any client documents,
/// and refusing it would break a client that speaks DPoP to several servers and
/// sends the header to all of them. It falls through to the door that IS
/// configured.
#[test]
fn a_proof_presented_to_a_broker_with_no_clients_configured_is_ignored_not_refused() {
    let (k, c, holder) = (
        keys("sk-broker-abc:tool-user"),
        ClientRegistry::default(),
        Key::new(),
    );
    let p = holder.proof(PATH, NOW, "j1");
    assert!(matches!(
        admit(
            door(&k, &c, false),
            Some("sk-broker-abc"),
            Some(&p),
            PATH,
            NOW
        ),
        Admission::Bearer(_)
    ));
}

// --- the proof door ---------------------------------------------------------

#[test]
fn a_valid_proof_opens_the_door_and_names_the_client_that_published_the_key() {
    let (holder, k) = (Key::new(), keys(""));
    let c = one_client(&holder);
    match admit(
        door(&k, &c, false),
        None,
        Some(&holder.proof(PATH, NOW, "j1")),
        PATH,
        NOW,
    ) {
        Admission::Proof(client_id) => assert_eq!(client_id, CLIENT),
        other => panic!("a good proof must be admitted: {other:?}"),
    }
}

/// The identity comes from the key that SIGNED the proof, never from anything
/// the caller asserts about itself (CLAUDE.md invariant 15's rule, one door
/// over). A key no configured client published names nobody.
#[test]
fn a_proof_from_a_key_no_client_published_is_refused() {
    let (holder, stranger, k) = (Key::new(), Key::new(), keys(""));
    let c = one_client(&holder);
    assert_eq!(
        admit(
            door(&k, &c, false),
            None,
            Some(&stranger.proof(PATH, NOW, "j1")),
            PATH,
            NOW
        ),
        Admission::Refused(DoorRefusal::UnknownClient)
    );
}

/// THE ONE THAT MAKES THIS WORTH HAVING HERE. Every call to this broker is a
/// POST to one URL, so `htm` and `htu` pin almost nothing: without single-use
/// `jti`, anybody who captures one request replays its proof against any other
/// JSON-RPC body for the rest of the window.
#[test]
fn a_replayed_proof_is_refused_though_it_verifies_perfectly() {
    let (holder, k) = (Key::new(), keys(""));
    let c = one_client(&holder);
    let p = holder.proof(PATH, NOW, "j1");
    assert!(matches!(
        admit(door(&k, &c, false), None, Some(&p), PATH, NOW),
        Admission::Proof(_)
    ));
    assert_eq!(
        admit(door(&k, &c, false), None, Some(&p), PATH, NOW),
        Admission::Refused(DoorRefusal::Replayed),
        "the same proof a second time is a replay, not a second request"
    );
}

/// The negative control for the test above: two DIFFERENT proofs from the same
/// key, one after the other, must both be admitted. Without this, a door that
/// refused every second call would pass the replay test.
#[test]
fn two_proofs_from_one_client_are_both_admitted() {
    let (holder, k) = (Key::new(), keys(""));
    let c = one_client(&holder);
    for jti in ["j1", "j2", "j3"] {
        assert!(
            matches!(
                admit(
                    door(&k, &c, false),
                    None,
                    Some(&holder.proof(PATH, NOW, jti)),
                    PATH,
                    NOW
                ),
                Admission::Proof(_)
            ),
            "a fresh proof is not a replay: {jti}"
        );
    }
}

#[test]
fn a_proof_for_another_path_or_another_moment_is_refused() {
    let (holder, k) = (Key::new(), keys(""));
    let c = one_client(&holder);
    // Signed for a path this request did not use.
    assert!(matches!(
        admit(
            door(&k, &c, false),
            None,
            Some(&holder.proof("/somewhere-else", NOW, "j1")),
            PATH,
            NOW
        ),
        Admission::Refused(DoorRefusal::BadProof)
    ));
    // Signed too long ago to be about this request.
    assert!(matches!(
        admit(
            door(&k, &c, false),
            None,
            Some(&holder.proof(PATH, NOW - 3600, "j2")),
            PATH,
            NOW
        ),
        Admission::Refused(DoorRefusal::BadProof)
    ));
}

#[test]
fn the_proof_door_alone_refuses_a_caller_that_presents_nothing() {
    let (holder, k) = (Key::new(), keys(""));
    let c = one_client(&holder);
    assert_eq!(
        admit(door(&k, &c, false), None, None, PATH, NOW),
        Admission::Refused(DoorRefusal::NoCredential)
    );
}

// --- the two doors together, which is the decision that matters -------------

/// The migration state: an operator adds a CIMD client while existing clients
/// still send `x-fuse-key`. Either satisfies, so nothing that worked yesterday
/// fails today. It is a state to leave, not a destination, which is why the
/// broker says so at startup (`bearer_door_still_open_warning`).
#[test]
fn with_both_doors_configured_a_bearer_key_and_no_proof_still_gets_in() {
    let (holder, k) = (Key::new(), keys("sk-broker-abc:tool-user"));
    let c = one_client(&holder);
    assert!(matches!(
        admit(door(&k, &c, false), Some("sk-broker-abc"), None, PATH, NOW),
        Admission::Bearer(_)
    ));
}

/// A caller that presents a proof is asking to be judged by it. A BROKEN proof
/// is therefore a refusal and never a downgrade to the weaker door, even when
/// the same call also carries a perfectly good bearer credential. This is
/// `delegation.rs`'s own rule one plane over: an accepted call with the binding
/// silently skipped looks exactly like it is working.
#[test]
fn a_broken_proof_is_never_downgraded_to_the_bearer_door() {
    let (holder, stranger, k) = (Key::new(), Key::new(), keys("sk-broker-abc:tool-user"));
    let c = one_client(&holder);
    assert_eq!(
        admit(
            door(&k, &c, false),
            Some("sk-broker-abc"),
            Some(&stranger.proof(PATH, NOW, "j1")),
            PATH,
            NOW
        ),
        Admission::Refused(DoorRefusal::UnknownClient),
        "a valid bearer key must not rescue a call whose proof failed"
    );
}

/// The way out of the migration state. With `TOKENFUSE_MCP_REQUIRE_PROOF` on, a
/// bearer credential alone stops being enough, and a captured `x-fuse-key`
/// header stops being a way in.
#[test]
fn require_proof_closes_the_bearer_door_without_removing_the_keys() {
    let (holder, k) = (Key::new(), keys("sk-broker-abc:tool-user"));
    let c = one_client(&holder);
    assert_eq!(
        admit(door(&k, &c, true), Some("sk-broker-abc"), None, PATH, NOW),
        Admission::Refused(DoorRefusal::NoCredential)
    );
    assert!(
        matches!(
            admit(
                door(&k, &c, true),
                Some("sk-broker-abc"),
                Some(&holder.proof(PATH, NOW, "j1")),
                PATH,
                NOW
            ),
            Admission::Proof(_)
        ),
        "the same client with a proof is still admitted"
    );
}

// --- what the configuration will and will not accept ------------------------

/// CIMD's client_id is an https URL. Permitting http would make the identity a
/// plaintext locator, and would hand any future dereference an unencrypted
/// target.
#[test]
fn an_http_client_id_is_refused_rather_than_quietly_accepted() {
    let holder = Key::new();
    let spec = serde_json::json!([document("http://release-bot.acme.example/c.json", &holder)])
        .to_string();
    assert!(ClientRegistry::from_spec(&spec, ORIGIN).is_err());
}

#[test]
fn a_client_id_that_is_not_a_url_at_all_is_refused() {
    let holder = Key::new();
    for id in ["release-bot", "", "ftp://acme.example/c.json", "https://"] {
        let spec = serde_json::json!([document(id, &holder)]).to_string();
        assert!(
            ClientRegistry::from_spec(&spec, ORIGIN).is_err(),
            "a client_id must be an absolute https URL: {id:?}"
        );
    }
}

#[test]
fn a_document_with_no_usable_key_is_refused() {
    for jwks in [
        serde_json::json!({"keys": []}),
        serde_json::json!({"keys": [{"kty": "oct", "k": "c2VjcmV0"}]}),
    ] {
        let spec = serde_json::json!([{"client_id": CLIENT, "jwks": jwks}]).to_string();
        assert!(
            ClientRegistry::from_spec(&spec, ORIGIN).is_err(),
            "a client with no key this broker can verify against is not a client: {jwks}"
        );
    }
}

/// The identity is derived from the key, so two clients publishing one key
/// would make it ambiguous. Refused at configuration time, where it is one
/// error message, rather than at request time, where it would be a coin toss.
#[test]
fn two_clients_publishing_one_key_is_refused_because_identity_would_be_ambiguous() {
    let holder = Key::new();
    let spec = serde_json::json!([
        document(CLIENT, &holder),
        document("https://other.acme.example/c.json", &holder),
    ])
    .to_string();
    assert!(ClientRegistry::from_spec(&spec, ORIGIN).is_err());
}

/// Set-but-unusable is never "off". Reading a typo as "no clients configured"
/// would leave the door in whatever state the OTHER variable happens to be in,
/// at the moment an operator believed they had just tightened it. Same
/// conclusion `clientkeys.rs` and `TOKENFUSE_MCP_SECRET_SCOPES` both reached.
#[test]
fn a_blank_spec_is_off_and_a_malformed_one_refuses_rather_than_reading_as_off() {
    assert!(!ClientRegistry::from_spec("", ORIGIN)
        .expect("blank is not configured")
        .enabled());
    assert!(!ClientRegistry::from_spec("   ", ORIGIN)
        .expect("whitespace is not configured")
        .enabled());
    for bad in ["not json", "{}", "[]", "[{\"jwks\":{\"keys\":[]}}]"] {
        assert!(
            ClientRegistry::from_spec(bad, ORIGIN).is_err(),
            "a spec that was set but yields no client must refuse: {bad:?}"
        );
    }
}

/// A configured proof door with no origin to compare `htu` against cannot check
/// which server a proof was made for, so it refuses to be built rather than
/// running with that check silently absent.
#[test]
fn client_documents_without_a_public_origin_refuse_to_be_configured() {
    let holder = Key::new();
    let spec = serde_json::json!([document(CLIENT, &holder)]).to_string();
    assert!(ClientRegistry::from_spec(&spec, "").is_err());
    assert!(ClientRegistry::from_spec(&spec, "   ").is_err());
}

/// The operator's deploy step writes the fetched documents to a file. Same
/// inline-or-path shape `TOKENFUSE_CLOUD_OIDC_JWKS` already uses, for the same
/// reason: a JWKS is too big to want in an environment variable and too
/// security-relevant to fetch at run time.
#[test]
fn the_documents_are_read_from_a_file_when_the_spec_is_a_path() {
    let holder = Key::new();
    let dir = std::env::temp_dir().join(format!("tf-mcp-door-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a temp dir");
    let path = dir.join("clients.json");
    std::fs::write(
        &path,
        serde_json::json!([document(CLIENT, &holder)]).to_string(),
    )
    .expect("write");
    let c = ClientRegistry::from_spec(path.to_str().expect("utf-8 path"), ORIGIN)
        .expect("a file of documents is a usable spec");
    assert!(c.enabled());
    assert!(matches!(
        admit(
            door(&keys(""), &c, false),
            None,
            Some(&holder.proof(PATH, NOW, "j1")),
            PATH,
            NOW
        ),
        Admission::Proof(_)
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A path that names nothing is a misconfiguration, not an empty allowlist.
#[test]
fn a_path_that_cannot_be_read_refuses_rather_than_reading_as_off() {
    assert!(ClientRegistry::from_spec("/no/such/file/clients.json", ORIGIN).is_err());
}
