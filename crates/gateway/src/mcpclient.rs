//! Minimal MCP client for the live scanner (`tokenfuse mcp-scan --url`):
//! Streamable HTTP transport only. Speaks the three-message handshake
//! (`initialize` → `notifications/initialized` → `tools/list`) as single POSTs
//! against one endpoint, per the MCP Streamable HTTP transport spec.
//!
//! SSE responses (the server choosing to stream its reply over
//! `text/event-stream`) are detected but not parsed — that's a follow-up
//! (`McpClientError::UnsupportedTransport`). This client is a bounded,
//! one-shot RPC: it exists to fetch a `tools/list` snapshot for scanning, not
//! to hold a long-lived session.

use std::time::Duration;

use serde_json::{json, Value};

/// Config for a single live `tools/list` fetch.
pub struct McpClientConfig {
    pub url: String,
    pub connect_timeout: Duration,
    pub total_timeout: Duration,
    /// Extra headers to send on every request (e.g. auth for the target MCP
    /// server). Sent as-is, in addition to `content-type` and `accept`.
    pub extra_headers: Vec<(String, String)>,
}

impl McpClientConfig {
    /// Build a config for `url`, reading timeouts from
    /// `TOKENFUSE_MCP_SCAN_CONNECT_TIMEOUT_SECS` (default 5) and
    /// `TOKENFUSE_MCP_SCAN_TIMEOUT_SECS` (default 15).
    pub fn new(url: impl Into<String>) -> Self {
        let connect_secs = std::env::var("TOKENFUSE_MCP_SCAN_CONNECT_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);
        let total_secs = std::env::var("TOKENFUSE_MCP_SCAN_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15);
        McpClientConfig {
            url: url.into(),
            connect_timeout: Duration::from_secs(connect_secs),
            total_timeout: Duration::from_secs(total_secs),
            extra_headers: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum McpClientError {
    #[error("request failed: {0}")]
    Transport(String),
    #[error("server returned HTTP {status}: {body}")]
    Status { status: u16, body: String },
    #[error("could not parse server response: {0}")]
    Parse(String),
    /// The server chose to stream its response as SSE (`text/event-stream`).
    /// Parsing that stream is a follow-up; PR1 only speaks single-shot JSON.
    #[error("{0}")]
    UnsupportedTransport(String),
}

/// Fetch a live `tools/list` snapshot over Streamable HTTP: `initialize`,
/// `notifications/initialized`, then `tools/list`, all as single POSTs to
/// `cfg.url`. Returns the raw `tools/list` JSON-RPC response value (the
/// `{"jsonrpc":..,"id":2,"result":{"tools":[...]}}` shape), which
/// `tokenfuse_core::mcp::parse_tools` accepts as-is.
pub async fn fetch_tools_list(cfg: &McpClientConfig) -> Result<Value, McpClientError> {
    let client = reqwest::Client::builder()
        .connect_timeout(cfg.connect_timeout)
        .timeout(cfg.total_timeout)
        .build()
        .map_err(|e| McpClientError::Transport(e.to_string()))?;

    let mut session_id: Option<String> = None;

    // (a) initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {
                "name": "tokenfuse-mcp-scan",
                "version": env!("CARGO_PKG_VERSION"),
            },
        },
    });
    let (init_resp, sid) = post_rpc(&client, cfg, &init_req, session_id.as_deref()).await?;
    let _ = init_resp; // handshake result body isn't needed beyond a successful round-trip
    if sid.is_some() {
        session_id = sid;
    }

    // (b) notifications/initialized — no id, no response body expected.
    let initialized = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    });
    send_notification(&client, cfg, &initialized, session_id.as_deref()).await?;

    // (c) tools/list
    let tools_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    });
    let (tools_resp, _) = post_rpc(&client, cfg, &tools_req, session_id.as_deref()).await?;
    Ok(tools_resp)
}

/// POST one JSON-RPC request expecting a JSON-RPC response, returning the
/// parsed body and any `Mcp-Session-Id` the server handed back.
async fn post_rpc(
    client: &reqwest::Client,
    cfg: &McpClientConfig,
    req: &Value,
    session_id: Option<&str>,
) -> Result<(Value, Option<String>), McpClientError> {
    let resp = send(client, cfg, req, session_id).await?;
    let status = resp.status();
    let sid = resp
        .headers()
        .get("Mcp-Session-Id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| McpClientError::Transport(e.to_string()))?;

    if !status.is_success() {
        return Err(McpClientError::Status {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }

    if content_type.starts_with("text/event-stream") {
        return Err(McpClientError::UnsupportedTransport(
            "server responded with SSE; streamable-SSE support lands in a follow-up".to_string(),
        ));
    }

    let value: Value =
        serde_json::from_slice(&bytes).map_err(|e| McpClientError::Parse(e.to_string()))?;
    Ok((value, sid))
}

/// Send a JSON-RPC notification (no `id`); the server may reply with an empty
/// 2xx body (e.g. 202 Accepted) — we don't parse it.
async fn send_notification(
    client: &reqwest::Client,
    cfg: &McpClientConfig,
    req: &Value,
    session_id: Option<&str>,
) -> Result<(), McpClientError> {
    let resp = send(client, cfg, req, session_id).await?;
    let status = resp.status();
    if !status.is_success() {
        let bytes = resp.bytes().await.unwrap_or_default();
        return Err(McpClientError::Status {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }
    Ok(())
}

/// Encode and POST a single JSON-RPC message. Manual encode (mirrors
/// `mcpbroker.rs`): the gateway crate does not enable reqwest's `json` feature.
async fn send(
    client: &reqwest::Client,
    cfg: &McpClientConfig,
    req: &Value,
    session_id: Option<&str>,
) -> Result<reqwest::Response, McpClientError> {
    let payload = serde_json::to_vec(req).map_err(|e| McpClientError::Parse(e.to_string()))?;
    let mut builder = client
        .post(&cfg.url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(sid) = session_id {
        builder = builder.header("Mcp-Session-Id", sid);
    }
    for (k, v) in &cfg.extra_headers {
        builder = builder.header(k, v);
    }
    builder
        .body(payload)
        .send()
        .await
        .map_err(|e| McpClientError::Transport(e.to_string()))
}
