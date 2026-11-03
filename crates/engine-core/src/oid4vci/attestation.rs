//! Client attestation (draft-ietf-oauth-attestation-based-client-auth):
//! the OAuth-Client-Attestation headers for the PAR and token requests,
//! and the `use_attestation_challenge` retry.
//!
//! **The WIA comes from the existing wallet provider** (go-wallet-
//! backend's `/wallet-provider/wia/challenge` + `/wia/generate`): the
//! engine asks the Host for the (WIA, PoP) pair — the Go engine's exact
//! contract (`SignActionRequestAttestation`) — because the instance key
//! that signs the PoPs lives on the device and never reaches the
//! engine. The core builds no JWT here; it forwards what the host
//! signed, resolves the server challenge when the AS demands one, and
//! re-asks with it.
//!
//! The P0.6-verified behaviours:
//! - Any host refusal leaves the flow without attestation and it
//!   proceeds (private_key_jwt or client_id remain); an issuer that
//!   requires attestation rejects on its own. Attestation is best-effort
//!   exactly like the Go engine's `requestClientAttestation`.
//! - The headers: `OAuth-Client-Attestation` (the WIA) and
//!   `OAuth-Client-Attestation-PoP` (the PoP), never one without the
//!   other.
//! - `use_attestation_challenge` (a 400/401 with that error code): the
//!   fresh challenge comes from the
//!   `OAuth-Client-Attestation-Challenge` response header first, else
//!   the AS's `challenge_endpoint` (POST; the same header on the
//!   answer, else the `attestation_challenge` body member). The host
//!   re-answers with a PoP bound to it, and the request retries once.
//! - PAR carries attestation but no DPoP proof (DPoP binds tokens, and
//!   PAR issues none).

use engine_ports::{
    AttestationParams, AttestationResult, FetchPurpose, HttpClient, HttpRequest, RedirectPolicy,
};

use super::types::AsMetadata;

/// The maximum size of a challenge endpoint response.
const MAX_CHALLENGE_BYTES: usize = 64 << 10;

/// The attestation pair the host supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAttestation {
    /// The WIA JWT (`oauth-client-attestation+jwt`).
    pub wia: String,
    /// The PoP JWT (`oauth-client-attestation-pop+jwt`).
    pub pop: String,
}

/// Why the attestation challenge resolution refused.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// The challenge endpoint answered an error.
    #[error("oid4vci: attestation challenge endpoint failed: {0}")]
    Endpoint(String),
    /// The transport failed.
    #[error("oid4vci: attestation challenge fetch failed: {0}")]
    Fetch(String),
}

/// Asks the host for the client attestation — best-effort, exactly the
/// Go rule: any refusal (a host without attestation support, a wallet
/// provider that is down, a missing instance key) proceeds without
/// attestation rather than failing the flow.
///
/// `challenge` is the server-provided challenge when the AS demanded
/// one; the host binds the fresh PoP to it.
pub async fn request_client_attestation(
    host: &dyn engine_ports::Host,
    flow_id: &str,
    audience: &str,
    client_id: &str,
    challenge: &str,
) -> Option<ClientAttestation> {
    let result = host
        .request_attestation(AttestationParams {
            flow_id: flow_id.to_owned(),
            audience: audience.to_owned(),
            client_id: client_id.to_owned(),
            challenge: challenge.to_owned(),
        })
        .await
        .ok()?;
    attestation_from(result)
}

/// The attestation pair from the host's answer — `None` when the host
/// supplied only one half or neither (never send the headers half-
/// equipped).
fn attestation_from(result: AttestationResult) -> Option<ClientAttestation> {
    if result.wia.is_empty() || result.pop.is_empty() {
        return None;
    }
    Some(ClientAttestation {
        wia: result.wia,
        pop: result.pop,
    })
}

/// The headers the attested request carries, when attestation is
/// available.
pub fn attestation_headers(attestation: Option<&ClientAttestation>) -> Vec<(String, String)> {
    match attestation {
        Some(attestation) => vec![
            (
                "OAuth-Client-Attestation".to_owned(),
                attestation.wia.clone(),
            ),
            (
                "OAuth-Client-Attestation-PoP".to_owned(),
                attestation.pop.clone(),
            ),
        ],
        None => Vec::new(),
    }
}

/// Whether an error response is the AS demanding a server-provided
/// challenge in the Client Attestation PoP: a 400/401 whose body's
/// `error` is `use_attestation_challenge`.
pub fn is_attestation_challenge_error(status: u16, body: &[u8]) -> bool {
    if status != 400 && status != 401 {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(|v| v.as_str())
                .map(|error| error == "use_attestation_challenge")
        })
        .unwrap_or(false)
}

/// The challenge from a response's `OAuth-Client-Attestation-Challenge`
/// header, when it carries one.
pub fn challenge_from_headers(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("OAuth-Client-Attestation-Challenge"))
        .map(|(_, value)| value.clone())
        .filter(|value| !value.is_empty())
}

/// Fetches a fresh challenge from the AS's `challenge_endpoint`.
///
/// The draft's convention: the challenge arrives in the
/// `OAuth-Client-Attestation-Challenge` response header; the
/// `{"attestation_challenge": ...}` body is the compatibility fallback
/// (the SDK's client-side path uses the body form, so both are
/// accepted).
pub async fn fetch_attestation_challenge(
    http: &dyn HttpClient,
    challenge_endpoint: &str,
) -> Result<String, AttestationError> {
    let response = http
        .send(HttpRequest {
            method: "POST".to_owned(),
            url: challenge_endpoint.to_owned(),
            headers: vec![
                ("accept".to_owned(), "application/json".to_owned()),
                ("content-type".to_owned(), "application/json".to_owned()),
            ],
            body: b"{}".to_vec(),
            purpose: FetchPurpose::Token,
            max_response_bytes: MAX_CHALLENGE_BYTES,
            redirects: RedirectPolicy::None,
            allow_plaintext: false,
            timeout_ms: 10_000,
        })
        .await
        .map_err(|err| AttestationError::Fetch(err.to_string()))?;

    if response.status != 200 {
        return Err(AttestationError::Endpoint(format!(
            "challenge endpoint answered {}",
            response.status
        )));
    }

    // The header first, else the body member.
    if let Some(challenge) = challenge_from_headers(&response.headers) {
        return Ok(challenge);
    }
    serde_json::from_slice::<serde_json::Value>(&response.body)
        .ok()
        .and_then(|value| {
            value
                .get("attestation_challenge")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .filter(|challenge| !challenge.is_empty())
        .ok_or_else(|| {
            AttestationError::Endpoint("challenge endpoint returned no challenge".to_owned())
        })
}

/// Resolves the fresh challenge after a `use_attestation_challenge`
/// rejection: the response header first, else the AS's
/// `challenge_endpoint`. `None` when no challenge could be obtained
/// (the retry is then impossible and the original error stands).
pub async fn resolve_challenge(
    http: &dyn HttpClient,
    as_metadata: &AsMetadata,
    response_headers: &[(String, String)],
) -> Option<String> {
    if let Some(challenge) = challenge_from_headers(response_headers) {
        return Some(challenge);
    }
    if as_metadata.challenge_endpoint.is_empty() {
        return None;
    }
    fetch_attestation_challenge(http, &as_metadata.challenge_endpoint)
        .await
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_ports::{HostError, HttpError, HttpResponse, SignParams, SignResult};

    struct AttestingHost {
        challenges: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl engine_ports::Host for AttestingHost {
        async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
            Ok(SignResult { signature: vec![] })
        }
        async fn request_match(
            &self,
            _f: &str,
            _e: Vec<engine_ports::MatchEntry>,
        ) -> Result<engine_ports::MatchResult, HostError> {
            Err(HostError::Cannot("no match".to_owned()))
        }
        async fn request_consent(
            &self,
            _p: engine_ports::ConsentParams,
        ) -> Result<engine_ports::ConsentResult, HostError> {
            Err(HostError::Cannot("no consent".to_owned()))
        }
        async fn request_tx_code(&self, _f: &str) -> Result<String, HostError> {
            Err(HostError::Cannot("no tx code".to_owned()))
        }
        async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
            Ok(())
        }
        fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}

        async fn request_attestation(
            &self,
            params: AttestationParams,
        ) -> Result<AttestationResult, HostError> {
            let pop = format!("pop-jwt-for-{}", params.challenge);
            self.challenges
                .lock()
                .map(|mut c| c.push(params.challenge))
                .ok();
            Ok(AttestationResult {
                wia: "wia-jwt".to_owned(),
                pop,
            })
        }
    }

    struct RefusingHost;
    #[async_trait::async_trait]
    impl engine_ports::Host for RefusingHost {
        async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
            Ok(SignResult { signature: vec![] })
        }
        async fn request_match(
            &self,
            _f: &str,
            _e: Vec<engine_ports::MatchEntry>,
        ) -> Result<engine_ports::MatchResult, HostError> {
            Err(HostError::Cannot("no match".to_owned()))
        }
        async fn request_consent(
            &self,
            _p: engine_ports::ConsentParams,
        ) -> Result<engine_ports::ConsentResult, HostError> {
            Err(HostError::Cannot("no consent".to_owned()))
        }
        async fn request_tx_code(&self, _f: &str) -> Result<String, HostError> {
            Err(HostError::Cannot("no tx code".to_owned()))
        }
        async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
            Ok(())
        }
        fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
    }

    // ─── the host request ────────────────────────────────────────────

    #[tokio::test]
    async fn an_answering_host_supplies_the_pair() {
        let host = AttestingHost {
            challenges: std::sync::Mutex::new(Vec::new()),
        };
        let attestation =
            request_client_attestation(&host, "flow-1", "https://as.example", "client-1", "")
                .await
                .expect("attestation");
        assert_eq!(attestation.wia, "wia-jwt");
        assert_eq!(attestation.pop, "pop-jwt-for-");
    }

    #[tokio::test]
    async fn a_refusing_host_proceeds_without_attestation() {
        assert!(
            request_client_attestation(&RefusingHost, "f", "https://as.example", "c", "")
                .await
                .is_none()
        );
        // The default implementation refuses too — an old host keeps
        // working, the flow proceeds unattested.
        struct OldHost;
        #[async_trait::async_trait]
        impl engine_ports::Host for OldHost {
            async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
                Ok(SignResult { signature: vec![] })
            }
            async fn request_match(
                &self,
                _f: &str,
                _e: Vec<engine_ports::MatchEntry>,
            ) -> Result<engine_ports::MatchResult, HostError> {
                Err(HostError::Cannot("no".to_owned()))
            }
            async fn request_consent(
                &self,
                _p: engine_ports::ConsentParams,
            ) -> Result<engine_ports::ConsentResult, HostError> {
                Err(HostError::Cannot("no".to_owned()))
            }
            async fn request_tx_code(&self, _f: &str) -> Result<String, HostError> {
                Err(HostError::Cannot("no".to_owned()))
            }
            async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
                Ok(())
            }
            fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
        }
        assert!(
            request_client_attestation(&OldHost, "f", "https://as.example", "c", "")
                .await
                .is_none()
        );
    }

    #[test]
    fn the_headers_come_as_a_pair_or_not_at_all() {
        let attestation = ClientAttestation {
            wia: "wia".to_owned(),
            pop: "pop".to_owned(),
        };
        let headers = attestation_headers(Some(&attestation));
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "OAuth-Client-Attestation");
        assert_eq!(headers[1].0, "OAuth-Client-Attestation-PoP");
        assert!(attestation_headers(None).is_empty());

        // A half answer is no answer.
        assert!(attestation_from(AttestationResult {
            wia: "wia".to_owned(),
            pop: String::new(),
        })
        .is_none());
    }

    // ─── the challenge rejection and resolution ──────────────────────

    #[test]
    fn the_challenge_rejection_is_recognized() {
        let body = br#"{"error":"use_attestation_challenge"}"#;
        assert!(is_attestation_challenge_error(400, body));
        assert!(is_attestation_challenge_error(401, body));
        assert!(!is_attestation_challenge_error(200, body));
        assert!(!is_attestation_challenge_error(
            400,
            br#"{"error":"invalid_client"}"#
        ));
        assert!(!is_attestation_challenge_error(400, b"not json"));
    }

    #[test]
    fn the_challenge_comes_from_the_response_header() {
        let headers = vec![(
            "OAuth-Client-Attestation-Challenge".to_owned(),
            "challenge-1".to_owned(),
        )];
        assert_eq!(
            challenge_from_headers(&headers),
            Some("challenge-1".to_owned())
        );
        assert_eq!(challenge_from_headers(&[]), None);
        // An empty header is no challenge.
        assert_eq!(
            challenge_from_headers(&[(
                "OAuth-Client-Attestation-Challenge".to_owned(),
                String::new()
            )]),
            None
        );
    }

    struct FakeHttp {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl HttpClient for FakeHttp {
        async fn send(&self, _request: HttpRequest) -> Result<HttpResponse, HttpError> {
            Ok(HttpResponse {
                status: self.status,
                headers: self.headers.clone(),
                body: self.body.clone(),
            })
        }
    }

    #[tokio::test]
    async fn the_challenge_endpoint_prefers_the_header_then_the_body() {
        let header = FakeHttp {
            status: 200,
            headers: vec![(
                "OAuth-Client-Attestation-Challenge".to_owned(),
                "from-header".to_owned(),
            )],
            body: br#"{"attestation_challenge":"from-body"}"#.to_vec(),
        };
        assert_eq!(
            fetch_attestation_challenge(&header, "https://as.example/challenge")
                .await
                .expect("challenge"),
            "from-header"
        );

        let body = FakeHttp {
            status: 200,
            headers: Vec::new(),
            body: br#"{"attestation_challenge":"from-body"}"#.to_vec(),
        };
        assert_eq!(
            fetch_attestation_challenge(&body, "https://as.example/challenge")
                .await
                .expect("challenge"),
            "from-body"
        );
    }

    #[tokio::test]
    async fn a_failed_challenge_endpoint_refuses() {
        let http = FakeHttp {
            status: 500,
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert!(fetch_attestation_challenge(&http, "https://as.example/c")
            .await
            .is_err());

        // No challenge in the answer at all.
        let empty = FakeHttp {
            status: 200,
            headers: Vec::new(),
            body: b"{}".to_vec(),
        };
        assert!(fetch_attestation_challenge(&empty, "https://as.example/c")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn the_challenge_resolution_prefers_the_header_then_the_endpoint() {
        let as_metadata = AsMetadata {
            issuer: "https://as.example".to_owned(),
            token_endpoint: "https://as.example/token".to_owned(),
            authorization_endpoint: String::new(),
            par_endpoint: String::new(),
            require_par: false,
            challenge_endpoint: "https://as.example/challenge".to_owned(),
            code_challenge_methods: None,
            grant_types: Vec::new(),
        };

        // The response header wins without touching the endpoint.
        let http = FakeHttp {
            status: 500, // would fail if called
            headers: vec![(
                "OAuth-Client-Attestation-Challenge".to_owned(),
                "from-header".to_owned(),
            )],
            body: Vec::new(),
        };
        assert_eq!(
            resolve_challenge(&http, &as_metadata, &http.headers.clone()).await,
            Some("from-header".to_owned())
        );

        // No header and no endpoint: no challenge.
        let bare = AsMetadata {
            challenge_endpoint: String::new(),
            ..as_metadata
        };
        assert_eq!(resolve_challenge(&http, &bare, &[]).await, None);
    }
}
