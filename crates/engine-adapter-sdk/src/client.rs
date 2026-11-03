//! The remote engine client: a thin WMP client the native SDKs use to
//! connect to a deployed engine server and run the session lifecycle —
//! the "remote engine" mode, for early testing before the in-process
//! engine lands.
//!
//! The client speaks the WMP HTTPS binding (POST `/wmp`) — the same
//! transport the server serves. It is intentionally minimal: create a
//! session, send a request, read the reply, close. The full client (with
//! the SSE notification stream) arrives with the flow families.

use std::sync::Arc;

use crate::{FetchPurpose, HeaderPair, HttpRequest, RedirectPolicy, SdkError};

/// A connection to a remote engine server. Holds the base URL and the
/// bearer token; each request goes through the host's HTTP port (so the
/// platform stack handles TLS, proxies and VPNs).
pub struct RemoteEngine {
    /// The engine server's base URL (e.g. `https://engine.example.com`).
    pub base_url: String,
    /// The bearer token, when the server requires one.
    pub bearer_token: Option<String>,
}

impl RemoteEngine {
    /// Connects to the engine at `base_url`.
    pub fn new(base_url: String) -> Arc<Self> {
        Arc::new(Self {
            base_url,
            bearer_token: None,
        })
    }

    /// Connects with a bearer token.
    pub fn with_token(self: &Arc<Self>, token: String) -> Arc<Self> {
        Arc::new(Self {
            base_url: self.base_url.clone(),
            bearer_token: Some(token),
        })
    }

    /// Sends one WMP request (a JSON-RPC message) to the engine and
    /// answers the reply. A notification answers `None`.
    pub async fn request(
        &self,
        http: &dyn crate::HttpClient,
        method: &str,
        params: serde_json::Value,
    ) -> Result<Option<serde_json::Value>, SdkError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": format!("req-{}", self.nonce()),
            "method": method,
            "params": params,
        });

        let mut headers = vec![HeaderPair {
            name: "content-type".to_owned(),
            value: "application/json".to_owned(),
        }];
        if let Some(token) = &self.bearer_token {
            headers.push(HeaderPair {
                name: "authorization".to_owned(),
                value: format!("Bearer {token}"),
            });
        }

        let request = HttpRequest {
            method: "POST".to_owned(),
            url: format!("{}/wmp", self.base_url),
            headers,
            body: serde_json::to_vec(&body).map_err(|_| SdkError::Internal)?,
            purpose: FetchPurpose::DirectPost,
            max_response_bytes: 1_048_576,
            redirects: RedirectPolicy::None,
            allow_plaintext: false,
            timeout_ms: 30_000,
        };

        let response = http.send(request).await?;
        if response.status != 200 {
            return Err(SdkError::Transport(format!(
                "engine answered {}",
                response.status
            )));
        }
        if response.body.is_empty() {
            return Ok(None);
        }

        let reply: serde_json::Value =
            serde_json::from_slice(&response.body).map_err(|_| SdkError::Internal)?;

        if let Some(error) = reply.get("error") {
            let code = error
                .get("code")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or_default();
            let message = error
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            return Err(SdkError::Transport(format!("WMP error {code}: {message}")));
        }

        Ok(reply.get("result").cloned())
    }

    /// Creates a session on the remote engine and answers the negotiated
    /// capabilities.
    pub async fn create_session(
        &self,
        http: &dyn crate::HttpClient,
        version: &str,
        security_mode: &str,
    ) -> Result<serde_json::Value, SdkError> {
        self.request(
            http,
            "wmp.session.create",
            serde_json::json!({
                "wmp": { "version": version },
                "security": { "mode": security_mode },
            }),
        )
        .await?
        .ok_or_else(|| SdkError::Transport("create answered no result".to_owned()))
    }

    fn nonce(&self) -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}
