//! RFC 9728 protected resource metadata at the MCP broker (WAVE1-DESIGN 1.5): the
//! document at the well-known path, the challenge a refused agent token is answered
//! with, the XAA document it shares a process with, and the two startup refusals.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};
use tokenfuse_delegation::testing::{agent_token, cfg, Key, AUD, ISS};
use tokenfuse_gateway::agenttoken::{AgentTokens, Mode};
use tokenfuse_gateway::chainproof::Proving;
use tokenfuse_gateway::clientkeys::ClientKeys;
use tokenfuse_gateway::mcpbroker::{app, BrokerState, ScanMode};
use tokenfuse_gateway::mcpdoor::PROOF_HEADER;
use tokenfuse_gateway::wardryx::Wardryx;
use tokenfuse_gateway::xaadoor::{resource_metadata_body, XaaDoor};

/// The origin the broker is told it is reached at; its proofs name it.
const BROKER_ORIGIN: &str = "https://mcp.acme.example";
/// The default resource: the audience the delegation door mints agent tokens for.
const RESOURCE: &str = AUD;
/// The bare well-known path RFC 9728 forms for a resource with no path.
const WELL_KNOWN: &str = "/.well-known/oauth-protected-resource";
/// The metadata URL a challenge names for the default resource.
const RESOURCE_METADATA: &str =
    "https://tokenfuse.acme.example/.well-known/oauth-protected-resource";

async fn serve_router(router: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    format!("http://{addr}")
}

/// One broker with the agent door at `mode` (none for off), XAA on or off, and
/// the resource its delegation audience names.
struct Door {
    issuer: Key,
    audience: String,
    mode: Option<Mode>,
    xaa: bool,
}

impl Door {
    fn new(mode: Option<Mode>) -> Self {
        Door {
            issuer: Key::new(),
            audience: RESOURCE.to_string(),
            mode,
            xaa: false,
        }
    }

    async fn serve(&self) -> String {
        let mut delegation = cfg(&self.issuer);
        delegation.audience = self.audience.clone();
        let state = Arc::new(BrokerState {
            chain_proof: Some(Arc::new(Proving {
                cfg: delegation,
                origin: BROKER_ORIGIN.to_string(),
            })),
            revocations: None,
            identity_strict: tokenfuse_gateway::identitymap::StrictMode::Off,
            upstream: "http://127.0.0.1:1".to_string(),
            named_upstreams: Default::default(),
            vault: tokenfuse_core::SecretVault::new(),
            scan: ScanMode::Off,
            dlp: tokenfuse_core::DlpMode::Off,
            dlp_pii: tokenfuse_core::DlpMode::Off,
            lock: None,
            drifted: Default::default(),
            wardryx: Arc::new(Wardryx::disabled()),
            keys: ClientKeys::from_spec("").expect("an empty key spec"),
            clients: Default::default(),
            require_proof: false,
            client: reqwest::Client::new(),
            events: Arc::new(tokenfuse_core::agent_event::Exporter::disabled()),
            taint_gateway: None,
            taint_failclosed: true,
            xaa: self.xaa.then(|| {
                Arc::new(XaaDoor {
                    cfg: cfg(&self.issuer),
                    resource: self.audience.clone(),
                })
            }),
            agent_tokens: self.mode.map(|m| Arc::new(AgentTokens::new(m))),
            taint_gateway_key: None,
        });
        let url = serve_router(app(state)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        url
    }
}

async fn fetch(url: &str, path: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!("{url}{path}"))
        .send()
        .await
        .unwrap()
}

/// A `tools/call` posted to `target` with the given headers.
async fn call(target: &str, headers: &[(&str, String)]) -> reqwest::Response {
    let mut req = reqwest::Client::new().post(target).json(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "gh_api", "arguments": {}}
    }));
    for (k, v) in headers {
        req = req.header(*k, v.as_str());
    }
    req.send().await.unwrap()
}

/// An agent token the door refuses. The issuer really minted it, for another
/// audience, so it is `typ: at+jwt` (the agent door judges that type alone, and
/// anything else goes to the delegation door) and its signature verifies; the
/// audience check is what refuses it. The proof names nothing, and is not reached.
fn refused_token(issuer: &Key) -> Vec<(&'static str, String)> {
    let now = tokenfuse_gateway::sink::now_millis() / 1000;
    let tok = agent_token(
        issuer,
        &Key::new(),
        now,
        json!({"aud": "https://elsewhere.example"}),
    );
    vec![
        ("authorization", format!("DPoP {tok}")),
        (PROOF_HEADER, "not-a-proof".to_string()),
    ]
}

fn challenge(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Under `accept` the document is served at the bare well-known path to anyone,
/// with no credential: a client reads it before it has a token to present.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_serves_the_document_without_credentials() {
    let url = Door::new(Some(Mode::Accept)).serve().await;
    let resp = fetch(&url, WELL_KNOWN).await;
    assert_eq!(resp.status(), 200);
    let doc: Value = resp.json().await.unwrap();
    assert_eq!(doc["resource"], json!(RESOURCE), "{doc}");
    assert_eq!(doc["authorization_servers"], json!([ISS]), "{doc}");
    assert_eq!(doc["bearer_methods_supported"], json!(["header"]), "{doc}");
    assert_eq!(
        doc["dpop_signing_alg_values_supported"],
        json!(["ES256"]),
        "{doc}"
    );
    assert_eq!(
        doc["dpop_bound_access_tokens_required"],
        json!(false),
        "{doc}"
    );
}

/// Under `require` every agent token is DPoP-bound, so the document says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn require_serves_the_document_with_bound_tokens_required() {
    let url = Door::new(Some(Mode::Require)).serve().await;
    let resp = fetch(&url, WELL_KNOWN).await;
    assert_eq!(resp.status(), 200);
    let doc: Value = resp.json().await.unwrap();
    assert_eq!(
        doc["dpop_bound_access_tokens_required"],
        json!(true),
        "{doc}"
    );
}

/// A resource with a path is published at the path-suffixed twin of the bare
/// well-known path (RFC 9728 section 3.1), and that document names the resource.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_resource_serves_its_suffixed_document() {
    let mut door = Door::new(Some(Mode::Accept));
    door.audience = "https://mcp.acme.example/mcp".to_string();
    let url = door.serve().await;
    let resp = fetch(&url, "/.well-known/oauth-protected-resource/mcp").await;
    assert_eq!(resp.status(), 200);
    let doc: Value = resp.json().await.unwrap();
    assert_eq!(
        doc["resource"],
        json!("https://mcp.acme.example/mcp"),
        "{doc}"
    );
}

/// With the agent door and XAA both off nothing new is routed: the well-known
/// path is not served, as it was not before this change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_both_doors_off_no_document_is_served() {
    let url = Door::new(None).serve().await;
    assert_eq!(fetch(&url, WELL_KNOWN).await.status(), 404);
}

/// A presented agent token that is refused is answered with the DPoP challenge,
/// the `error` parameter RFC 6750 reserves for a presented token, and the
/// metadata URL built from the configured resource.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_token_is_challenged_with_dpop_and_invalid_token() {
    let door = Door::new(Some(Mode::Accept));
    let url = door.serve().await;
    let resp = call(&url, &refused_token(&door.issuer)).await;
    assert_eq!(resp.status(), 401);
    let expected = format!(
        "DPoP algs=\"ES256\", error=\"invalid_token\", resource_metadata=\"{RESOURCE_METADATA}\""
    );
    assert_eq!(challenge(&resp).as_deref(), Some(expected.as_str()));
}

/// A call with no credential under `require` is challenged with the DPoP scheme
/// and the metadata, and no `error` parameter: RFC 6750 sends that only for a
/// token that was presented.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_credential_under_require_is_challenged_without_an_error_parameter() {
    let url = Door::new(Some(Mode::Require)).serve().await;
    let resp = call(&url, &[]).await;
    assert_eq!(resp.status(), 401);
    let expected = format!("DPoP algs=\"ES256\", resource_metadata=\"{RESOURCE_METADATA}\"");
    assert_eq!(challenge(&resp).as_deref(), Some(expected.as_str()));
}

/// The origin in the challenge is the configured resource's, never the `Host`
/// header a caller writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_challenge_origin_comes_from_configuration_not_the_host_header() {
    let url = Door::new(Some(Mode::Require)).serve().await;
    let resp = call(&url, &[("host", "evil.example".to_string())]).await;
    assert_eq!(resp.status(), 401);
    let value = challenge(&resp).unwrap_or_default();
    assert!(value.contains(RESOURCE_METADATA), "{value}");
    assert!(!value.contains("evil.example"), "{value}");
}

/// A resource with a path names its path-suffixed document in the challenge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_resource_challenge_names_its_suffixed_document() {
    let mut door = Door::new(Some(Mode::Require));
    door.audience = "https://mcp.acme.example/mcp".to_string();
    let url = door.serve().await;
    let resp = call(&format!("{url}/mcp"), &[]).await;
    assert_eq!(resp.status(), 401);
    let expected = "DPoP algs=\"ES256\", resource_metadata=\"https://mcp.acme.example/.well-known/oauth-protected-resource/mcp\"";
    assert_eq!(challenge(&resp).as_deref(), Some(expected));
}

/// With XAA on too, the document is XAA's own with the agent fields added, and it
/// still does not say bound tokens are required: an XAA bearer token is unbound
/// and is admitted under `require`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_xaa_the_document_adds_the_agent_fields_and_never_requires_bound_tokens() {
    let mut door = Door::new(Some(Mode::Require));
    door.xaa = true;
    let url = door.serve().await;
    let resp = fetch(&url, WELL_KNOWN).await;
    assert_eq!(resp.status(), 200);
    let doc: Value = resp.json().await.unwrap();
    assert_eq!(doc["resource"], json!(RESOURCE), "{doc}");
    assert_eq!(doc["authorization_servers"], json!([ISS]), "{doc}");
    assert_eq!(doc["bearer_methods_supported"], json!(["header"]), "{doc}");
    assert_eq!(
        doc["dpop_signing_alg_values_supported"],
        json!(["ES256"]),
        "{doc}"
    );
    assert_eq!(
        doc["dpop_bound_access_tokens_required"],
        json!(false),
        "{doc}"
    );
}

/// XAA alone publishes exactly the document it always has: the agent door adds
/// nothing when it is off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xaa_alone_serves_the_xaa_document_unchanged() {
    let mut door = Door::new(None);
    door.xaa = true;
    let url = door.serve().await;
    let resp = fetch(&url, WELL_KNOWN).await;
    assert_eq!(resp.status(), 200);
    let doc: Value = resp.json().await.unwrap();
    let expected = resource_metadata_body(&XaaDoor {
        cfg: cfg(&door.issuer),
        resource: RESOURCE.to_string(),
    });
    assert_eq!(doc, expected, "{doc}");
}

/// With XAA on beside the agent door, a refused agent token is still answered
/// with the DPoP challenge naming the document.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_xaa_a_refused_agent_token_is_still_challenged_with_dpop() {
    let mut door = Door::new(Some(Mode::Accept));
    door.xaa = true;
    let url = door.serve().await;
    let resp = call(&url, &refused_token(&door.issuer)).await;
    assert_eq!(resp.status(), 401);
    let value = challenge(&resp).unwrap_or_default();
    assert!(value.contains("DPoP algs=\"ES256\""), "{value}");
    assert!(value.contains(RESOURCE_METADATA), "{value}");
}

/// A refused agent token gets the agent door's own body, the one a refused token
/// gets at the LLM door, not the generic unauthorized body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_token_gets_the_agent_token_refused_body() {
    let door = Door::new(Some(Mode::Accept));
    let url = door.serve().await;
    let resp = call(&url, &refused_token(&door.issuer)).await;
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"]["type"],
        json!("agent_token_refused"),
        "{body}"
    );
}

/// A call with no agent token under `require` gets the required body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_credential_under_require_gets_the_agent_token_required_body() {
    let url = Door::new(Some(Mode::Require)).serve().await;
    let resp = call(&url, &[]).await;
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"]["type"],
        json!("agent_token_required"),
        "{body}"
    );
}

/// The document's `resource` and the challenge's metadata URL name the same
/// resource, because both are built from one configuration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_document_and_the_challenge_name_the_same_resource() {
    let door = Door::new(Some(Mode::Accept));
    let url = door.serve().await;
    let resp = fetch(&url, WELL_KNOWN).await;
    assert_eq!(resp.status(), 200);
    let doc: Value = resp.json().await.unwrap();
    let resource = doc["resource"].as_str().unwrap_or_default().to_string();
    assert!(
        !resource.is_empty(),
        "the document names no resource: {doc}"
    );
    let refused = call(&url, &refused_token(&door.issuer)).await;
    let value = challenge(&refused).unwrap_or_default();
    let expected = format!("resource_metadata=\"{resource}/.well-known/oauth-protected-resource\"");
    assert!(value.contains(&expected), "{value}");
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tokenfuse")
}

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a.to_string()
}

/// The broker as the stacks run it, with the variables a test names set on top.
fn broker(extra: &[(&str, String)]) -> Command {
    let mut cmd = Command::new(bin());
    cmd.arg("mcp-broker")
        .env("TOKENFUSE_MCP_UPSTREAM", "http://127.0.0.1:1")
        .env("TOKENFUSE_MCP_ADDR", free_addr())
        .env_remove("TOKENFUSE_MCP_KEYS")
        .env_remove("TOKENFUSE_MCP_ACCEPT_XAA")
        .env_remove("TOKENFUSE_MCP_RESOURCE")
        .env_remove("TOKENFUSE_AGENT_TOKENS")
        .env_remove("TOKENFUSE_DELEGATION_ISSUER")
        .env_remove("TOKENFUSE_DELEGATION_JWKS")
        .env_remove("TOKENFUSE_DELEGATION_URL")
        .env_remove("TOKENFUSE_DELEGATION_AUDIENCE")
        .env_remove("TOKENFUSE_DELEGATION_REVOCATIONS");
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd
}

fn start(mut cmd: Command) -> Child {
    cmd.stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the tokenfuse binary")
}

/// Waits for the process to exit, up to a ceiling; `None` if it is still running.
fn exits_within(child: &mut Child) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Exit 2, and stderr names every one of `names`. A process still running is
/// killed before the test fails, so a red run leaves nothing listening.
fn refused(mut child: Child, what: &str, names: &[&str]) {
    let Some(status) = exits_within(&mut child) else {
        child.kill().ok();
        child.wait().ok();
        panic!("{what}: the process kept running instead of refusing to start");
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .ok();
    assert_eq!(status.code(), Some(2), "{what}: stderr was: {stderr}");
    for name in names {
        assert!(
            stderr.contains(name),
            "{what}: stderr did not name {name}: {stderr}"
        );
    }
}

/// A revocation list that answers with nothing revoked and a current cursor, so
/// the one thing a startup test gets wrong is the one thing it names.
async fn list_server() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let list = Router::new().route(
        "/v1/revocations",
        get(|| async {
            let now = tokenfuse_gateway::sink::now_millis() / 1000;
            Json(json!({"revocations": [], "as_of": now}))
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(l, list).await;
    });
    addr.to_string()
}

/// A key set with one key, in a file only the test with this label names: every
/// test in this binary shares one process id.
fn write_jwks(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "tf-protected-resource-{label}-{}.json",
        std::process::id()
    ));
    std::fs::write(
        &path,
        json!({"keys": [Key::new().jwk_value(Some("v-1"))]}).to_string(),
    )
    .unwrap();
    path
}

/// An agent audience that is not an absolute https URL cannot be the resource the
/// document names, so the broker refuses to start, naming the variable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_audience_that_is_not_https_refuses_to_start() {
    let list = list_server().await;
    let jwks = write_jwks("audience");
    let child = start(broker(&[
        ("TOKENFUSE_AGENT_TOKENS", "accept".to_string()),
        ("TOKENFUSE_DELEGATION_ISSUER", ISS.to_string()),
        ("TOKENFUSE_DELEGATION_JWKS", jwks.display().to_string()),
        ("TOKENFUSE_DELEGATION_URL", AUD.to_string()),
        (
            "TOKENFUSE_DELEGATION_AUDIENCE",
            "tokenfuse-broker".to_string(),
        ),
        (
            "TOKENFUSE_DELEGATION_REVOCATIONS",
            format!("http://{list}/v1/revocations"),
        ),
    ]));
    let result = tokio::task::spawn_blocking(move || {
        refused(
            child,
            "a non-https audience",
            &["TOKENFUSE_DELEGATION_AUDIENCE"],
        )
    })
    .await;
    let _ = std::fs::remove_file(&jwks);
    result.unwrap();
}

/// XAA names one resource and the agent door another: one document cannot name
/// both, so the broker refuses to start, naming both variables.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_xaa_resource_that_differs_from_the_agent_audience_refuses_to_start() {
    let list = list_server().await;
    let jwks = write_jwks("xaa-resource");
    let child = start(broker(&[
        ("TOKENFUSE_AGENT_TOKENS", "accept".to_string()),
        ("TOKENFUSE_DELEGATION_ISSUER", ISS.to_string()),
        ("TOKENFUSE_DELEGATION_JWKS", jwks.display().to_string()),
        ("TOKENFUSE_DELEGATION_URL", AUD.to_string()),
        (
            "TOKENFUSE_DELEGATION_AUDIENCE",
            "https://mcp.acme.example/mcp".to_string(),
        ),
        (
            "TOKENFUSE_DELEGATION_REVOCATIONS",
            format!("http://{list}/v1/revocations"),
        ),
        ("TOKENFUSE_MCP_ACCEPT_XAA", "on".to_string()),
        (
            "TOKENFUSE_MCP_RESOURCE",
            "https://tokenfuse.acme.example/other".to_string(),
        ),
    ]));
    let result = tokio::task::spawn_blocking(move || {
        refused(
            child,
            "an XAA resource that differs from the agent audience",
            &["TOKENFUSE_MCP_RESOURCE", "TOKENFUSE_DELEGATION_AUDIENCE"],
        )
    })
    .await;
    let _ = std::fs::remove_file(&jwks);
    result.unwrap();
}
