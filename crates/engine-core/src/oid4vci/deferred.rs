//! Deferred credential polling: the `transaction_id` + `interval` loop, and
//! the notification afterwards — the S2 pieces after the initial request.

use engine_ports::{Clock, FetchPurpose, HttpClient, HttpError, HttpRequest, RedirectPolicy};

use super::credential::CredentialResponse;
use super::token::TokenResponse;
use super::types::IssuerMetadata;

/// The maximum size of a deferred credential response: 4 MiB.
const MAX_DEFERRED_BYTES: usize = 4 << 20;

/// The maximum number of polling attempts: 60 (5 minutes at 5s intervals,
/// per the Go engine's `pollDeferredCredential`).
const MAX_ATTEMPTS: usize = 60;

/// Why the deferred polling refused.
#[derive(Debug, thiserror::Error)]
pub enum DeferredError {
    /// The deferred endpoint answered a non-200/non-202.
    #[error("oid4vci: deferred endpoint answered {0}")]
    Status(u16),
    /// The transport failed.
    #[error("oid4vci: deferred polling failed: {0}")]
    Fetch(String),
    /// The response is not a credential response.
    #[error("oid4vci: deferred response is not JSON")]
    NotJson,
    /// The polling timed out (the credential never arrived).
    #[error("oid4vci: deferred credential timed out after {0} attempts")]
    Timeout(usize),
}

/// Polls the deferred credential endpoint until the credential is ready
/// or the polling times out.
///
/// The P0.6-verified behaviour:
/// - The endpoint: `{credential_issuer}/deferred_credential`.
/// - The interval: from the credential response's `interval` (the issuer's
///   own, in seconds; default 5).
/// - The maximum: 60 attempts (≈5 minutes at the default interval).
/// - The request carries the same access token; a 200 answers the
///   credential; a 202 answers "not yet, keep polling".
pub async fn poll_deferred_credential(
    http: &dyn HttpClient,
    clock: &dyn Clock,
    metadata: &IssuerMetadata,
    token: &TokenResponse,
    transaction_id: &str,
    interval_secs: Option<i64>,
    on_progress: &(dyn Fn(usize) + Sync),
) -> Result<CredentialResponse, DeferredError> {
    let deferred_endpoint = format!(
        "{}/deferred_credential",
        metadata.credential_issuer.trim_end_matches('/')
    );
    let interval_ms = interval_secs.unwrap_or(5).max(1).saturating_mul(1000) as u64;

    let request_body = serde_json::json!({ "transaction_id": transaction_id });

    for attempt in 0..MAX_ATTEMPTS {
        // Sleep the interval before each poll (the first poll waits too —
        // the issuer said "not ready" by answering the transaction_id).
        clock.sleep(interval_ms).await;
        on_progress(attempt + 1);

        let response = http
            .send(HttpRequest {
                method: "POST".to_owned(),
                url: deferred_endpoint.clone(),
                headers: vec![
                    ("content-type".to_owned(), "application/json".to_owned()),
                    (
                        "authorization".to_owned(),
                        format!("Bearer {}", token.access_token),
                    ),
                ],
                body: serde_json::to_vec(&request_body).unwrap_or_default(),
                purpose: FetchPurpose::Deferred,
                max_response_bytes: MAX_DEFERRED_BYTES,
                redirects: RedirectPolicy::None,
                allow_plaintext: false,
                timeout_ms: 30_000,
            })
            .await
            .map_err(|err| match err {
                HttpError::Refused => DeferredError::Fetch("refused by the adapter".to_owned()),
                HttpError::Transport(detail) => DeferredError::Fetch(detail),
            })?;

        match response.status {
            200 => {
                // The credential is ready.
                let value: serde_json::Value =
                    serde_json::from_slice(&response.body).map_err(|_| DeferredError::NotJson)?;
                let credential: CredentialResponse =
                    serde_json::from_value(value).map_err(|_| DeferredError::NotJson)?;
                return Ok(credential);
            }
            202 => {
                // Not yet: keep polling.
                continue;
            }
            status => return Err(DeferredError::Status(status)),
        }
    }

    Err(DeferredError::Timeout(MAX_ATTEMPTS))
}

/// Why the notification refused.
#[derive(Debug, thiserror::Error)]
pub enum NotificationError {
    /// The transport failed (best effort; the notification does not fail
    /// the flow).
    #[error("oid4vci: notification failed: {0}")]
    Fetch(String),
}

/// Sends the credential notification to the issuer's notification endpoint
/// (OID4VCI §10): the lifecycle event (accepted or failure).
///
/// The notification is best effort: a failure logs but does not fail the
/// flow — the credential is already received.
pub async fn send_notification(
    http: &dyn HttpClient,
    metadata: &IssuerMetadata,
    notification_id: &str,
    event: &str,
) -> Result<(), NotificationError> {
    // The notification endpoint: the metadata's `notification_endpoint`
    // when it carries one (the P0.6-verified Go behaviour), else the
    // constructed fallback.
    let endpoint = if metadata.notification_endpoint.is_empty() {
        format!(
            "{}/notification",
            metadata.credential_issuer.trim_end_matches('/')
        )
    } else {
        metadata.notification_endpoint.clone()
    };

    let body = serde_json::json!({
        "notification_id": notification_id,
        "event": event,
    });

    let _ = http
        .send(HttpRequest {
            method: "POST".to_owned(),
            url: endpoint,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: serde_json::to_vec(&body).unwrap_or_default(),
            purpose: FetchPurpose::Notification,
            max_response_bytes: 1024,
            redirects: RedirectPolicy::None,
            allow_plaintext: false,
            timeout_ms: 10_000,
        })
        .await;

    // Best effort: the notification does not fail the flow.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeHttp {
        status: u16,
        body: Vec<u8>,
        calls: std::sync::Mutex<usize>,
    }

    impl FakeHttp {
        fn credential_ready() -> Self {
            Self {
                status: 200,
                body: br#"{"credential":"jwt-credential"}"#.to_vec(),
                calls: std::sync::Mutex::new(0),
            }
        }

        fn pending() -> Self {
            Self {
                status: 202,
                body: Vec::new(),
                calls: std::sync::Mutex::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for FakeHttp {
        async fn send(&self, _r: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
            let _ = self.calls.lock().map(|mut c| *c += 1);
            assert_eq!(_r.purpose, FetchPurpose::Deferred);
            Ok(engine_ports::HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }

    struct InstantClock;

    #[async_trait::async_trait]
    impl Clock for InstantClock {
        fn now_unix(&self) -> i64 {
            0
        }
        async fn sleep(&self, _duration_ms: u64) {}
    }

    fn test_metadata() -> IssuerMetadata {
        IssuerMetadata {
            nonce_endpoint: None,
            credential_endpoint: String::new(),
            token_endpoint: String::new(),
            notification_endpoint: String::new(),
            credential_issuer: "https://issuer.example".to_owned(),
            authorization_servers: Vec::new(),
            credential_configurations: serde_json::json!({}),
            signed_metadata: None,
            is_signed: false,
        }
    }

    fn test_token() -> TokenResponse {
        TokenResponse {
            access_token: "at-deferred".to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in: Some(3600),
            refresh_token: None,
            c_nonce: None,
            nonce: None,
            authorization_details: None,
        }
    }

    #[tokio::test]
    async fn polls_until_the_credential_is_ready() {
        let http = FakeHttp::credential_ready();
        let result = poll_deferred_credential(
            &http,
            &InstantClock,
            &test_metadata(),
            &test_token(),
            "tx-1",
            Some(1),
            &|_| {},
        )
        .await
        .expect("credential");
        assert!(result.credential.is_some());
        assert_eq!(*http.calls.lock().expect("lock"), 1);
    }

    #[tokio::test]
    async fn times_out_after_the_max_attempts() {
        let http = FakeHttp::pending();
        let err = poll_deferred_credential(
            &http,
            &InstantClock,
            &test_metadata(),
            &test_token(),
            "tx-2",
            Some(1),
            &|_| {},
        )
        .await
        .expect_err("timeout");
        assert!(matches!(err, DeferredError::Timeout(60)));
        assert_eq!(*http.calls.lock().expect("lock"), 60);
    }

    #[tokio::test]
    async fn a_non_200_non_202_is_terminal() {
        let http = FakeHttp {
            status: 404,
            body: Vec::new(),
            calls: std::sync::Mutex::new(0),
        };
        assert!(matches!(
            poll_deferred_credential(
                &http,
                &InstantClock,
                &test_metadata(),
                &test_token(),
                "tx-3",
                Some(1),
                &|_| {},
            )
            .await,
            Err(DeferredError::Status(404))
        ));
    }
}
