//! Nonce handling: the `invalid_nonce` retry-once loop, the nonce endpoint,
//! and the legacy `c_nonce` fallback — the P0.6-verified behaviour.
//!
//! The Go engine's exact rule (P0.6): "On invalid_nonce (or any body
//! carrying a refreshed c_nonce): fresh nonce from nonce endpoint first,
//! then legacy c_nonce in the body; retry once; terminal after the second."

use engine_ports::{FetchPurpose, Host, HttpClient, HttpRequest, RedirectPolicy};

/// The maximum size of a nonce endpoint response: 1 MiB.
const MAX_NONCE_BYTES: usize = 1 << 20;

/// Why the nonce handling refused.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum NonceError {
    /// The nonce endpoint was advertised but the fetch failed.
    #[error("oid4vci: nonce endpoint failed: {0}")]
    EndpointFailed(String),
    /// The credential response carried `invalid_nonce` twice: terminal.
    #[error("oid4vci: invalid_nonce after retry: terminal")]
    Terminal,
    /// Neither the nonce endpoint nor a `c_nonce` was available.
    #[error("oid4vci: no nonce source available")]
    NoSource,
}

/// The result of a nonce handling step: the fresh nonce to retry with, or
/// the terminal error.
#[derive(Debug, PartialEq)]
pub enum NonceOutcome {
    /// A fresh nonce was obtained; retry the credential request with it.
    RetryWith(String),
    /// The credential response did not carry `invalid_nonce`; no retry.
    NoRetry,
    /// The retry was already used; terminal.
    Terminal(NonceError),
}

/// Detects whether a credential response carries `invalid_nonce`, and
/// resolves the fresh nonce to retry with.
///
/// The P0.6-verified behaviour:
/// - The credential response's error body carries `"error": "invalid_nonce"`.
/// - The retry nonce comes from (in order):
///   1. The issuer's nonce endpoint, when the metadata advertises it.
///   2. The response body's `c_nonce` member (the legacy fallback).
/// - The retry happens exactly once; a second `invalid_nonce` is terminal.
/// - The retry re-sends the same auxiliary data and encryption offer.
pub async fn handle_invalid_nonce(
    http: &dyn HttpClient,
    host: &dyn Host,
    response_body: &[u8],
    nonce_endpoint: Option<&str>,
    has_retried: bool,
) -> Result<NonceOutcome, NonceError> {
    // Parse the response body to check for invalid_nonce.
    let body: serde_json::Value =
        serde_json::from_slice(response_body).unwrap_or(serde_json::Value::Null);

    // Check for invalid_nonce in the error.
    let is_invalid_nonce = body
        .get("error")
        .and_then(|v| v.as_str())
        .map(|e| e == "invalid_nonce")
        .unwrap_or(false);

    // Also check for a c_nonce in a successful response (a nonce refresh).
    let c_nonce = body
        .get("c_nonce")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    if !is_invalid_nonce {
        if !c_nonce.is_empty() {
            // A successful response with a fresh c_nonce: use it for the
            // next credential request, but no retry needed.
            return Ok(NonceOutcome::NoRetry);
        }
        return Ok(NonceOutcome::NoRetry);
    }

    // Terminal after the retry.
    if has_retried {
        return Ok(NonceOutcome::Terminal(NonceError::Terminal));
    }

    // Resolve the fresh nonce: the endpoint first, then c_nonce.
    if let Some(endpoint) = nonce_endpoint {
        if !endpoint.is_empty() {
            if let Ok(nonce) = fetch_nonce(http, host, endpoint, None).await {
                return Ok(NonceOutcome::RetryWith(nonce));
            }
        }
    }

    // The c_nonce fallback.
    if !c_nonce.is_empty() {
        return Ok(NonceOutcome::RetryWith(c_nonce));
    }

    Ok(NonceOutcome::Terminal(NonceError::NoSource))
}

/// Fetches a nonce from the issuer's nonce endpoint (OpenID4VCI §7).
///
/// Public for the credential request's initial nonce resolution and the
/// `invalid_nonce` retry: the endpoint is preferred over the legacy
/// `c_nonce` fallback in both places.
pub async fn fetch_nonce(
    http: &dyn HttpClient,
    host: &dyn Host,
    endpoint: &str,
    aux: Option<&super::credential::CredentialRequestAux<'_>>,
) -> Result<String, NonceError> {
    // OID4VCI 1.0 §8: the wallet POSTs to the nonce endpoint. A
    // DPoP-bound flow proves the request too (RFC 9449 §4.3) — with the
    // nonce retry the resource server's `use_dpop_nonce` demand asks
    // for (RFC 9449 §8.1), starting from the token response's nonce.
    let dpop = aux.and_then(|aux| aux.dpop.as_ref());
    let mut dpop_nonce = dpop.and_then(|dpop| dpop.dpop_nonce).map(str::to_owned);
    let mut response: Option<engine_ports::HttpResponse> = None;
    for attempt in 0..2 {
        let mut headers = vec![("accept".to_owned(), "application/json".to_owned())];
        if let Some(dpop) = dpop {
            if let Some(proof) = super::dpop::proof_for(
                host,
                Some(dpop.key),
                super::dpop::ProofRequest {
                    flow_id: dpop.flow_id,
                    key_id: dpop.key_id,
                    htm: "POST",
                    htu: endpoint,
                    access_token: None,
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
        let sent = http
            .send(HttpRequest {
                method: "POST".to_owned(),
                url: endpoint.to_owned(),
                headers,
                body: Vec::new(),
                purpose: FetchPurpose::Nonce,
                max_response_bytes: MAX_NONCE_BYTES,
                redirects: RedirectPolicy::Max(5),
                allow_plaintext: false,
                timeout_ms: 10_000,
            })
            .await
            .map_err(|err| NonceError::EndpointFailed(err.to_string()))?;
        if attempt == 1 || !super::dpop::is_dpop_nonce_error(&sent) {
            response = Some(sent);
            break;
        }
        dpop_nonce = super::dpop::dpop_nonce_from_response(&sent);
    }
    let response = response.expect("the loop always stores the last response");

    if response.status != 200 {
        return Err(NonceError::EndpointFailed(format!(
            "nonce endpoint answered {}",
            response.status
        )));
    }

    let body: serde_json::Value = serde_json::from_slice(&response.body)
        .map_err(|_| NonceError::EndpointFailed("not JSON".to_owned()))?;

    let nonce = body
        .get("nonce")
        .or_else(|| body.get("c_nonce"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    if nonce.is_empty() {
        return Err(NonceError::EndpointFailed(
            "no nonce in the response".to_owned(),
        ));
    }

    Ok(nonce)
}

/// The test host: answers nothing beyond the sign asks the nonce
/// path never makes when no DPoP binding rides the aux.
struct TestHost;

#[async_trait::async_trait]
impl Host for TestHost {
    async fn request_sign(
        &self,
        _p: engine_ports::SignParams,
    ) -> Result<engine_ports::SignResult, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot("no keys in the test".to_owned()))
    }
    async fn request_match(
        &self,
        _p: engine_ports::MatchParams,
    ) -> Result<engine_ports::MatchResult, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot("no match in the test".to_owned()))
    }
    async fn request_consent(
        &self,
        _p: engine_ports::ConsentParams,
    ) -> Result<engine_ports::ConsentResult, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot("no consent in the test".to_owned()))
    }
    async fn request_tx_code(&self, _f: &str) -> Result<String, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot(
            "no tx code in the test".to_owned(),
        ))
    }
    async fn open_authorization(
        &self,
        _f: &str,
        _u: &str,
    ) -> Result<(), engine_ports::HostError> {
        Ok(())
    }
    fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_ports::HttpError;

    struct FakeHttp {
        status: u16,
        body: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl HttpClient for FakeHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            assert_eq!(request.purpose, FetchPurpose::Nonce);
            Ok(engine_ports::HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }

    #[tokio::test]
    async fn an_invalid_nonce_from_the_endpoint_retries() {
        let http = FakeHttp {
            status: 200,
            body: br#"{"nonce":"fresh-1"}"#.to_vec(),
        };
        let response = br#"{"error":"invalid_nonce"}"#;
        let outcome = handle_invalid_nonce(&http, &TestHost, response, Some("https://i.example/nonce"), false)
            .await
            .expect("handle");
        assert_eq!(outcome, NonceOutcome::RetryWith("fresh-1".to_owned()));
    }

    #[tokio::test]
    async fn the_c_nonce_fallback_when_no_endpoint() {
        let http = FakeHttp {
            status: 500,
            body: Vec::new(),
        };
        let response = br#"{"error":"invalid_nonce","c_nonce":"c-1"}"#;
        let outcome = handle_invalid_nonce(&http, &TestHost, response, None, false)
            .await
            .expect("handle");
        assert_eq!(outcome, NonceOutcome::RetryWith("c-1".to_owned()));
    }

    #[tokio::test]
    async fn terminal_after_the_retry() {
        let http = FakeHttp {
            status: 200,
            body: b"{}".to_vec(),
        };
        let response = br#"{"error":"invalid_nonce","c_nonce":"c-1"}"#;
        let outcome = handle_invalid_nonce(&http, &TestHost, response, Some("https://i.example/nonce"), true)
            .await
            .expect("handle");
        assert!(matches!(
            outcome,
            NonceOutcome::Terminal(NonceError::Terminal)
        ));
    }

    #[tokio::test]
    async fn a_non_error_response_needs_no_retry() {
        let http = FakeHttp {
            status: 200,
            body: Vec::new(),
        };
        let response = br#"{"credential":"jwt"}"#;
        let outcome = handle_invalid_nonce(&http, &TestHost, response, None, false)
            .await
            .expect("handle");
        assert_eq!(outcome, NonceOutcome::NoRetry);
    }

    #[tokio::test]
    async fn no_source_available_is_terminal() {
        let http = FakeHttp {
            status: 500,
            body: Vec::new(),
        };
        let response = br#"{"error":"invalid_nonce"}"#;
        let outcome = handle_invalid_nonce(&http, &TestHost, response, None, false)
            .await
            .expect("handle");
        assert!(matches!(
            outcome,
            NonceOutcome::Terminal(NonceError::NoSource)
        ));
    }
}
