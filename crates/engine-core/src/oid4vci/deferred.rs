//! Deferred credential polling: the `transaction_id` + `interval` loop, and
//! the notification afterwards — the S2 pieces after the initial request.

use engine_ports::{Clock, FetchPurpose, Host, HttpClient, HttpError, HttpRequest, RedirectPolicy};

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
//
// The argument count is the shape: the poller mirrors the credential
// request it follows (the token, the DPoP binding, the transaction it
// polls, the issuer's interval, the progress hook), so the parameters
// ride loose instead of a nested context.
#[allow(clippy::too_many_arguments)]
pub async fn poll_deferred_credential(
    http: &dyn HttpClient,
    host: &dyn Host,
    clock: &dyn Clock,
    metadata: &IssuerMetadata,
    token: &TokenResponse,
    dpop: Option<&super::credential::ResourceDpop<'_>>,
    transaction_id: &str,
    interval_secs: Option<i64>,
    on_progress: &(dyn Fn(usize) + Sync),
) -> Result<CredentialResponse, DeferredError> {
    // The deferred credential endpoint: the metadata's
    // `deferred_credential_endpoint` (OID4VCI 1.0 §9), else the
    // constructed fallback.
    let deferred_endpoint = metadata
        .deferred_credential_endpoint
        .as_deref()
        .filter(|e| !e.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "{}/deferred_credential",
                metadata.credential_issuer.trim_end_matches('/')
            )
        });
    let interval_ms = interval_secs.unwrap_or(5).max(1).saturating_mul(1000) as u64;

    let request_body = serde_json::json!({ "transaction_id": transaction_id });
    // The sender-constrained binding (RFC 9449 §4.3): a DPoP-bound
    // token authorizes with the DPoP scheme and a fresh `ath`-bound
    // proof per poll, the resource nonce threading along.
    let dpop_bound = token.token_type.eq_ignore_ascii_case("DPoP");
    let mut dpop_nonce = dpop.and_then(|dpop| dpop.dpop_nonce).map(str::to_owned);

    for attempt in 0..MAX_ATTEMPTS {
        // Sleep the interval before each poll (the first poll waits too —
        // the issuer said "not ready" by answering the transaction_id).
        clock.sleep(interval_ms).await;
        on_progress(attempt + 1);

        // The nonce retry (RFC 9449 §8.1): a use_dpop_nonce demand
        // re-proofs and re-sends this poll once before giving up on it.
        let mut response: Option<engine_ports::HttpResponse> = None;
        for retry in 0..2 {
            let authorization = if dpop_bound {
                format!("DPoP {}", token.access_token)
            } else {
                format!("Bearer {}", token.access_token)
            };
            let mut headers = vec![
                ("content-type".to_owned(), "application/json".to_owned()),
                ("authorization".to_owned(), authorization),
            ];
            if dpop_bound {
                if let Some(dpop) = dpop {
                    if let Some(proof) = super::dpop::proof_for(
                        host,
                        Some(dpop.key),
                        super::dpop::ProofRequest {
                            flow_id: dpop.flow_id,
                            key_id: dpop.key_id,
                            htm: "POST",
                            htu: &deferred_endpoint,
                            access_token: Some(&token.access_token),
                            nonce: dpop_nonce.as_deref(),
                            rng: dpop.rng,
                            now_unix: dpop.now_unix,
                        },
                    )
                    .await
                    {
                        headers.push(("DPoP".to_owned(), proof));
                    }
                }
            }
            let sent = http
                .send(HttpRequest {
                    method: "POST".to_owned(),
                    url: deferred_endpoint.clone(),
                    headers,
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
            if retry == 1 || !super::dpop::is_dpop_nonce_error(&sent) {
                response = Some(sent);
                break;
            }
            dpop_nonce = super::dpop::dpop_nonce_from_response(&sent);
        }
        let response = match response {
            Some(response) => response,
            // Unreachable: the last attempt always stores its response
            // before it breaks.
            None => {
                return Err(DeferredError::Fetch(
                    "the deferred endpoint never answered".to_owned(),
                ))
            }
        };

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
    host: &dyn Host,
    metadata: &IssuerMetadata,
    token: Option<&super::token::TokenResponse>,
    dpop: Option<&super::credential::ResourceDpop<'_>>,
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

    // The sender-constrained binding (RFC 9449 §4.3): a DPoP-bound
    // token authorizes the notification like any other resource
    // request — the DPoP scheme with a fresh `ath`-bound proof, the
    // nonce retry included (§8.1).
    let dpop_token = token.filter(|token| token.token_type.eq_ignore_ascii_case("DPoP"));
    let mut dpop_nonce = dpop.and_then(|dpop| dpop.dpop_nonce).map(str::to_owned);
    for attempt in 0..2 {
        let mut headers = vec![("content-type".to_owned(), "application/json".to_owned())];
        if let Some(token) = dpop_token {
            headers.push((
                "authorization".to_owned(),
                format!("DPoP {}", token.access_token),
            ));
            if let Some(dpop) = dpop {
                if let Some(proof) = super::dpop::proof_for(
                    host,
                    Some(dpop.key),
                    super::dpop::ProofRequest {
                        flow_id: dpop.flow_id,
                        key_id: dpop.key_id,
                        htm: "POST",
                        htu: &endpoint,
                        access_token: Some(&token.access_token),
                        nonce: dpop_nonce.as_deref(),
                        rng: dpop.rng,
                        now_unix: dpop.now_unix,
                    },
                )
                .await
                {
                    headers.push(("DPoP".to_owned(), proof));
                }
            }
        }

        let response = http
            .send(HttpRequest {
                method: "POST".to_owned(),
                url: endpoint.clone(),
                headers,
                body: serde_json::to_vec(&body).unwrap_or_default(),
                purpose: FetchPurpose::Notification,
                max_response_bytes: 1024,
                redirects: RedirectPolicy::None,
                allow_plaintext: false,
                timeout_ms: 10_000,
            })
            .await;

        // The nonce demand (RFC 9449 §8.1): one retry with the fresh
        // nonce; the notification is best effort either way.
        match response {
            Ok(response) => {
                if attempt == 0 && super::dpop::is_dpop_nonce_error(&response) {
                    dpop_nonce = super::dpop::dpop_nonce_from_response(&response);
                    continue;
                }
            }
            Err(_) => break,
        }
        break;
    }

    // Best effort: the notification does not fail the flow.
    Ok(())
}
