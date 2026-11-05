//! The OpenID4VP flow family: request parsing, verifier trust, credential
//! selection, transaction data, VP signing, and response submission — S4's
//! presentation flow, built on the same `FlowHandler` seam.

pub mod dcql;
pub mod jarm;
pub mod request;
pub mod response;
pub mod transaction_data;
pub mod trust;
pub mod types;

use trust::TrustError;
use wmp_core::handler::HandlerError;
use wmp_core::methods::*;

use crate::runtime::{FlowContext, FlowHandler};

/// A test utility for base64url encoding (shared across the oid4vp tests).
pub mod test_util;

/// The OID4VP flow handler: the full presentation flow — parse the request,
/// evaluate the verifier's trust, ask the host for credential selection
/// and consent, validate the transaction data, request the VP signature,
/// and submit the response.
pub struct Oid4vpFlow;

#[async_trait::async_trait]
impl FlowHandler for Oid4vpFlow {
    fn flow_types(&self) -> Vec<String> {
        vec!["oid4vp".to_owned()]
    }

    fn required_capability(&self, _flow_type: &str) -> String {
        "flows".to_owned()
    }

    async fn start_flow(
        &self,
        ctx: &FlowContext,
        params: &FlowStartParams,
    ) -> Result<FlowStartResult, HandlerError> {
        let flow_error = |reason: String| {
            wmp_core::error::RpcError::new(
                wmp_core::error::ERR_FLOW_ERROR,
                Some(serde_json::json!({ "reason": reason })),
            )
        };

        // Parse the authorization request from the flow start's params.
        let raw_params = params
            .params
            .as_deref()
            .map(|raw| raw.get())
            .unwrap_or_default();
        let request_params = serde_json::from_str::<serde_json::Value>(raw_params)
            .unwrap_or(serde_json::Value::Null);

        // The outer request URI, when the flow start carried one (the
        // params value is the URL the QR code / link named). The §5
        // validations compare the request object against it. The raw
        // params member is the JSON text — the URL form arrives as a
        // JSON string, its quotes the RawValue's, not the URL's.
        let outer_request_uri = match &request_params {
            serde_json::Value::String(url) => url.clone(),
            _ => String::new(),
        };

        // The Go engine's step vocabulary: message steps around each
        // phase (docs/engine-parity.md §2) — the drop-in surface the
        // SDK's FlowStepCatalog and the frontend's UI state machine key on.
        let _ = ctx
            .progress(
                "parsing_request",
                &serde_json::json!({ "message": "parsing the authorization request" }),
            )
            .await;

        let mut auth_req = request::parse_request(ctx.http().as_ref(), &request_params)
            .await
            .map_err(|err| flow_error(err.to_string()))?;

        let _ = ctx
            .progress(
                "request_parsed",
                &serde_json::json!({
                    "client_id": auth_req.client_id,
                    "response_mode": auth_req.response_mode.as_str(),
                }),
            )
            .await;

        // The §5 validations: the outer/inner client_id agreement
        // (RFC 9101 §5.2), and — for x509_san_dns with direct_post — the
        // response_uri origin match.
        trust::validate_client_id_match(&auth_req, &outer_request_uri)
            .map_err(|err| flow_error(err.to_string()))?;
        trust::validate_response_uri_origin(&auth_req, &outer_request_uri)
            .map_err(|err| flow_error(err.to_string()))?;

        // Resolve the client metadata (inline, else the bounded fetch)
        // and build the verifier info. A failed fetch continues without
        // the metadata — the name falls back to the client_id.
        let client_metadata = trust::resolve_client_metadata(ctx.http().as_ref(), &auth_req).await;
        let mut verifier = trust::build_verifier_info(&auth_req, client_metadata.as_ref());

        // Store the resolved metadata on the request so the downstream
        // steps (the JARM submission's encryption parameters) see it —
        // the Go behaviour, and the only way a metadata-by-URI request
        // can be answered encrypted.
        if let Some(metadata) = &client_metadata {
            auth_req.client_metadata = Some(metadata.raw.clone());
        }

        // The verifier trust through the PDP port — fail closed: a PDP
        // error is never equivalent to "no PDP configured" and never
        // falls back to asking the client (P0.6).
        let _ = ctx
            .progress(
                "evaluating_verifier_trust",
                &serde_json::json!({ "message": "evaluating the verifier trust" }),
            )
            .await;

        trust::evaluate_verifier_trust(
            ctx.pdp().as_ref(),
            &auth_req,
            client_metadata.as_ref(),
            &mut verifier,
        )
        .await
        .map_err(|err| match &err {
            // The typed -31006 data (go-wmp's NewUntrustedVerifierData):
            // the class reason, the refused verifier, the PDP's detail,
            // and the retryable flag.
            TrustError::Untrusted { verifier, reason } => {
                HandlerError::Rpc(wmp_core::error::RpcError::new(
                    wmp_core::error::ERR_FLOW_ERROR,
                    Some(trust::untrusted_verifier_data(verifier, reason)),
                ))
            }
            _ => HandlerError::Rpc(flow_error(err.to_string())),
        })?;

        let _ = ctx
            .progress(
                "trust_evaluated",
                &serde_json::json!({
                    "verifier_trust_evaluated": true,
                    "verifier": verifier.client_id,
                    "verifier_name": verifier.name,
                    "trusted": verifier.trusted,
                    "framework": verifier.framework,
                    "reason": verifier.reason,
                }),
            )
            .await;

        // Validate the transaction data against the DCQL query.
        let transaction_data = transaction_data::validate_transaction_data(
            &auth_req.transaction_data_raw,
            &auth_req.dcql_query,
        )
        .map_err(|err| flow_error(err.to_string()))?;

        let _ = ctx
            .progress(
                "transaction_data_validated",
                &serde_json::json!({
                    "count": transaction_data.len(),
                }),
            )
            .await;

        // Ask the host to match the wallet's credentials against the
        // query and select what to present — the local matching is the
        // host's (the wallet state and the credential formats live
        // there), exactly the Go engine's credentials_matched
        // contract. An empty answer ends the flow: nothing to present
        // is not an error.
        let match_result = ctx
            .host()
            .request_match(engine_ports::MatchParams {
                flow_id: params.flow_id.clone(),
                dcql_query: auth_req.dcql_query.clone(),
                scope: auth_req.scope.clone(),
                verifier: verifier.clone(),
                transaction_data: auth_req.transaction_data_raw.clone(),
            })
            .await
            .map_err(|err| flow_error(err.to_string()))?;

        if match_result.selections.is_empty()
            || !dcql::unsatisfied_required_queries(
                auth_req.dcql_query.as_ref(),
                &match_result.selections,
            )
            .is_empty()
        {
            // Nothing matched, or a required DCQL query has no
            // credential: the DCQL contract (OID4VP 1.0 §6.2, §6.4.2)
            // answers with `access_denied` — never a partial vp_token.
            // A scope-only request with nothing matched ends silently
            // (the Go engine's empty credentials_matched).
            let unsatisfied = dcql::unsatisfied_required_queries(
                auth_req.dcql_query.as_ref(),
                &match_result.selections,
            );
            if !unsatisfied.is_empty() || auth_req.dcql_query.is_some() {
                let _ = response::submit_error_response(
                    ctx.http().as_ref(),
                    &auth_req,
                    "access_denied",
                    // The same description as the decline: the verifier
                    // must not tell a refusal from an empty wallet apart
                    // (the Go engine's verifierRefusedDescription).
                    "The wallet did not fulfil the request",
                )
                .await;
            }
            let _ = ctx
                .progress(
                    "no_matching_credential",
                    &serde_json::json!({
                        "requested": dcql::requested_credential_types(auth_req.dcql_query.as_ref()),
                        "unsatisfied": unsatisfied,
                    }),
                )
                .await;
            let _ = ctx
                .complete(&serde_json::json!({ "matched": false, "refused": true }))
                .await;
            return Ok(FlowStartResult {
                wmp: wmp_core::types::Metadata::default(),
                flow_id: params.flow_id.clone(),
                flow_type: params.flow_type.clone(),
            });
        }

        let _ = ctx
            .progress(
                "credential_selection",
                &serde_json::json!({
                    "count": match_result.selections.len(),
                    "credential_ids": match_result
                        .selections
                        .iter()
                        .map(|s| s.credential_id.clone())
                        .collect::<Vec<_>>(),
                }),
            )
            .await;

        // Ask the host's user for consent.
        let consent = ctx
            .host()
            .request_consent(engine_ports::ConsentParams {
                flow_id: params.flow_id.clone(),
                purpose: auth_req.scope.clone(),
                requested_claims: match_result
                    .selections
                    .iter()
                    .flat_map(|s| s.disclosed_claims.iter().cloned())
                    .collect(),
                transaction_data: auth_req.transaction_data_raw.clone(),
            })
            .await
            .map_err(|err| flow_error(err.to_string()))?;

        if !consent.consented {
            // The decline: a plain form POST, never encrypted (P0.6).
            let _ = response::submit_error_response(
                ctx.http().as_ref(),
                &auth_req,
                "access_denied",
                // The same description as the empty-match refusal: the
                // verifier must not tell a decline from an empty wallet
                // apart (the Go engine's verifierRefusedDescription).
                "The wallet did not fulfil the request",
            )
            .await;
            let _ = ctx.complete(&serde_json::json!({ "declined": true })).await;
            return Ok(FlowStartResult {
                wmp: wmp_core::types::Metadata::default(),
                flow_id: params.flow_id.clone(),
                flow_type: params.flow_type.clone(),
            });
        }

        // Ask the host to construct and sign the VP token — the
        // wallet's presentation formats and key custody live there
        // (the Go SignActionSignPresentation). The verifier JWK
        // thumbprint rides along for direct_post.jwt's
        // OpenID4VPHandover transcript; the verifier's session id
        // (the `sessionId` query parameter) for the ZK/PPID
        // verifier_context.
        let vp_result = ctx
            .host()
            .request_vp(engine_ports::VpParams {
                flow_id: params.flow_id.clone(),
                audience: if !auth_req.client_id.is_empty() {
                    auth_req.client_id.clone()
                } else {
                    auth_req.redirect_uri.clone()
                },
                nonce: auth_req.nonce.clone(),
                selections: match_result.selections.clone(),
                response_uri: if !auth_req.response_uri.is_empty() {
                    auth_req.response_uri.clone()
                } else {
                    auth_req.redirect_uri.clone()
                },
                verifier_jwk_thumbprint: jarm::verifier_jwk_thumbprint(&auth_req),
                verifier_session_id: trust::query_param(&outer_request_uri, "sessionId")
                    .unwrap_or_default(),
                transaction_data: auth_req.transaction_data_raw.clone(),
            })
            .await
            .map_err(|err| flow_error(err.to_string()))?;

        let vp_token = vp_result.vp_token;

        // The DCQL vp_token assembly (OID4VP §8.1): a newline-separated
        // answer restructures into the object keyed by credential query
        // id; a host that returned a JSON object passes through.
        let vp_token = if auth_req.dcql_query.is_some() {
            dcql::build_dcql_vp_token(&vp_token, &match_result.selections)
                .map_err(|err| flow_error(err.to_string()))?
        } else {
            vp_token
        };

        // The Go engine's `submitting_response` message step before the
        // submission (docs/engine-parity.md §2).
        let _ = ctx
            .progress(
                "submitting_response",
                &serde_json::json!({ "message": "submitting the presentation" }),
            )
            .await;

        // Submit the response per the request's response mode. The
        // Clock port supplies the JARM `iat`/`exp`.
        let submission = response::submit_response(
            ctx.http().as_ref(),
            &auth_req,
            &vp_token,
            ctx.clock().now_unix(),
        )
        .await
        .map_err(|err| flow_error(err.to_string()))?;

        // The direct_post answer's `redirect_uri` (OID4VP §8.2): a
        // user-agent step — the wallet opens it in the end-user's
        // browser, never as a back-channel fetch. The open_authorization
        // port is exactly that navigation. The plain submission returns
        // the answer body (its redirect_uri member); the JARM submission
        // returns the extracted redirect URL itself.
        let redirect_uri = if submission.starts_with("http") {
            Some(submission.clone())
        } else {
            serde_json::from_str::<serde_json::Value>(&submission)
                .ok()
                .and_then(|value| {
                    value
                        .get("redirect_uri")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned)
                })
                .filter(|uri| !uri.is_empty())
        };
        if let Some(uri) = redirect_uri {
            let _ = ctx.host().open_authorization(&params.flow_id, &uri).await;
            let _ = ctx
                .progress(
                    "redirect_opened",
                    &serde_json::json!({ "redirect_uri": uri }),
                )
                .await;
        }

        let _ = ctx
            .complete(&serde_json::json!({
                "presented": true,
                "credential_ids": match_result
                    .selections
                    .iter()
                    .map(|s| s.credential_id.clone())
                    .collect::<Vec<_>>(),
            }))
            .await;

        Ok(FlowStartResult {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: params.flow_id.clone(),
            flow_type: params.flow_type.clone(),
        })
    }

    async fn handle_action(
        &self,
        _ctx: &FlowContext,
        _params: &FlowActionParams,
    ) -> Result<FlowActionResult, HandlerError> {
        Err(wmp_core::error::RpcError::code(wmp_core::error::ERR_METHOD_NOT_FOUND).into())
    }

    async fn handle_progress(&self, _ctx: &FlowContext, _params: &FlowProgressParams) {}
    async fn handle_complete(&self, _ctx: &FlowContext, _params: &FlowCompleteParams) {}
    async fn handle_error(&self, _ctx: &FlowContext, _params: &FlowErrorParams) {}

    async fn handle_cancel(
        &self,
        _ctx: &FlowContext,
        _params: &FlowCancelParams,
    ) -> Result<bool, HandlerError> {
        Ok(true)
    }
}

#[cfg(test)]
mod presentation_flow_tests {
    //! The presentation flow, end to end on scripted ports: the request,
    //! the trust evaluation, the match with the DCQL query and the
    //! verifier, the consent, the host-constructed VP token, the DCQL
    //! assembly, and the submission.

    use super::*;
    use crate::runtime::{FlowContext, FlowHandler};
    use crate::Ports;
    use engine_ports::{
        AttestationParams, AttestationResult, ConsentParams, ConsentResult, DpopProofParams,
        DpopProofResult, EvaluationRequest, EvaluationResponse, Host, HostError, HttpClient,
        HttpError, HttpRequest, HttpResponse, KeyValue, KeyValueEntry, MatchParams, MatchResult,
        Pdp, PdpError, ResolveRequest, ResolveResponse, Rng, SignParams, SignResult, VpParams,
        VpResult, VpSelection,
    };
    use std::sync::{Arc, Mutex};

    struct TrustedPdp;
    #[async_trait::async_trait]
    impl Pdp for TrustedPdp {
        async fn evaluate(
            &self,
            _request: EvaluationRequest,
        ) -> Result<EvaluationResponse, PdpError> {
            Ok(EvaluationResponse {
                trusted: true,
                decision: Some("in the registry".to_owned()),
            })
        }
        async fn resolve(&self, _request: ResolveRequest) -> Result<ResolveResponse, PdpError> {
            Err(PdpError::NotImplemented)
        }
    }

    /// The host that answers the whole ask chain and records what it
    /// was asked.
    struct RecordingHost {
        matches: Mutex<Vec<MatchParams>>,
        vps: Mutex<Vec<VpParams>>,
    }

    #[async_trait::async_trait]
    impl Host for RecordingHost {
        async fn request_sign(&self, _params: SignParams) -> Result<SignResult, HostError> {
            Err(HostError::Cannot(
                "no plain sign in the presentation test".to_owned(),
            ))
        }
        async fn request_match(&self, params: MatchParams) -> Result<MatchResult, HostError> {
            self.matches.lock().map(|mut m| m.push(params)).ok();
            Ok(MatchResult {
                selections: vec![
                    VpSelection {
                        credential_query_id: "pid-query".to_owned(),
                        credential_id: "cred-pid".to_owned(),
                        disclosed_claims: vec!["given_name".to_owned()],
                    },
                    VpSelection {
                        credential_query_id: "degree-query".to_owned(),
                        credential_id: "cred-degree".to_owned(),
                        disclosed_claims: Vec::new(),
                    },
                ],
            })
        }
        async fn request_consent(
            &self,
            _params: ConsentParams,
        ) -> Result<ConsentResult, HostError> {
            Ok(ConsentResult { consented: true })
        }
        async fn request_tx_code(&self, _flow_id: &str) -> Result<String, HostError> {
            Err(HostError::Cannot("no tx code".to_owned()))
        }
        async fn open_authorization(&self, _flow_id: &str, _url: &str) -> Result<(), HostError> {
            Ok(())
        }
        async fn request_vp(&self, params: VpParams) -> Result<VpResult, HostError> {
            self.vps.lock().map(|mut v| v.push(params)).ok();
            Ok(VpResult {
                vp_token: "token-pid\ntoken-degree".to_owned(),
            })
        }
        async fn request_dpop_proof(
            &self,
            _params: DpopProofParams,
        ) -> Result<DpopProofResult, HostError> {
            Err(HostError::Cannot("no client-held dpop".to_owned()))
        }
        async fn request_attestation(
            &self,
            _params: AttestationParams,
        ) -> Result<AttestationResult, HostError> {
            Err(HostError::Cannot("no attestation".to_owned()))
        }
        fn progress(&self, _flow_id: &str, _step: &str, _detail: Option<String>) {}
    }

    /// The scripted HTTP: one answer per URL.
    struct ScriptedHttp {
        answers: Mutex<Vec<(String, HttpResponse)>>,
        seen: Mutex<Vec<HttpRequest>>,
    }

    impl ScriptedHttp {
        fn new(answers: Vec<(String, HttpResponse)>) -> Self {
            Self {
                answers: Mutex::new(answers),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for ScriptedHttp {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
            self.seen.lock().map(|mut s| s.push(request.clone())).ok();
            let answer = self.answers.lock().ok().and_then(|mut a| {
                a.iter()
                    .position(|(url, _)| *url == request.url)
                    .map(|index| a.remove(index).1)
            });
            Ok(answer.unwrap_or(HttpResponse {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
            }))
        }
    }

    fn test_context(host: Arc<RecordingHost>, http: Arc<ScriptedHttp>) -> FlowContext {
        let store = Arc::new(wmp_core::session::MemorySessionStore::new());
        let handler = Arc::new(wmp_core::sessionservice::SessionHandler::new(
            Arc::new(
                wmp_core::sessionservice::SessionService::new(
                    wmp_core::sessionservice::SessionServiceConfig {
                        store: Some(store.clone()),
                        entropy: Some(Arc::new(|bytes: &mut [u8]| {
                            for (i, b) in bytes.iter_mut().enumerate() {
                                *b = i as u8;
                            }
                            true
                        })),
                        ..wmp_core::sessionservice::SessionServiceConfig::default()
                    },
                )
                .unwrap_or_else(|_| panic!("session service")),
            ),
            Arc::new(|| 0),
        ));
        let peer = wmp_core::peer::PeerBuilder::new(handler)
            .session_store(store)
            .build();
        FlowContext {
            flow_id: "flow-vp-1".to_owned(),
            flow_type: "oid4vp".to_owned(),
            session: None,
            ports: Arc::new(Ports {
                http,
                clock: Arc::new(FixedClock),
                rng: Arc::new(FakeRng),
                host,
                pdp: Arc::new(TrustedPdp),
                kv: Arc::new(MemKv(Mutex::new(rustc_hash::FxHashMap::default()))),
                telemetry: Arc::new(NoTelemetry),
            }),
            peer,
            request_context: wmp_core::context::RequestContext::default(),
        }
    }

    pub(super) struct FixedClock;
    #[async_trait::async_trait]
    impl engine_ports::Clock for FixedClock {
        fn now_unix(&self) -> i64 {
            1_000
        }
        async fn sleep(&self, _duration_ms: u64) {}
    }

    pub(super) struct FakeRng;
    impl Rng for FakeRng {
        fn fill(&self, buf: &mut [u8]) -> bool {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = i as u8;
            }
            true
        }
    }

    pub(super) struct MemKv(pub(super) Mutex<rustc_hash::FxHashMap<String, Vec<u8>>>);
    #[async_trait::async_trait]
    impl KeyValue for MemKv {
        async fn get(&self, key: &str) -> Option<KeyValueEntry> {
            self.0.lock().ok()?.get(key).map(|v| KeyValueEntry {
                value: v.clone(),
                ttl_secs: None,
            })
        }
        async fn put(&self, key: &str, entry: KeyValueEntry) {
            self.0
                .lock()
                .map(|mut m| m.insert(key.to_owned(), entry.value))
                .ok();
        }
        async fn delete(&self, key: &str) {
            self.0.lock().map(|mut m| m.remove(key)).ok();
        }
    }

    pub(super) struct NoTelemetry;
    impl engine_ports::Telemetry for NoTelemetry {
        fn event(&self, _event: engine_ports::TelemetryEvent) {}
    }

    /// A params Box<RawValue> from a JSON value.
    fn raw_value(value: serde_json::Value) -> Option<Box<serde_json::value::RawValue>> {
        serde_json::value::RawValue::from_string(value.to_string()).ok()
    }

    pub(super) fn start_params() -> FlowStartParams {
        FlowStartParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-vp-1".to_owned(),
            flow_type: "oid4vp".to_owned(),
            params: raw_value(serde_json::json!({
                // The redirect_uri scheme: the x509_san_dns scheme now
                // requires the signed request form (§5), which the plain
                // params cannot carry.
                "client_id": "https://verifier.example",
                "nonce": "nonce-vp-1",
                "response_uri": "https://verifier.example/response",
                "response_mode": "direct_post",
                "state": "state-vp-1",
                "dcql_query": {
                    "credentials": [
                        { "id": "pid-query", "meta": { "vct_values": ["urn:pid"] } },
                        { "id": "degree-query", "meta": { "vct_values": ["urn:degree"] } }
                    ]
                }
            })),
            timeout: None,
        }
    }

    #[tokio::test]
    async fn the_presentation_flow_matches_consents_and_presents() {
        let host = Arc::new(RecordingHost {
            matches: Mutex::new(Vec::new()),
            vps: Mutex::new(Vec::new()),
        });
        let http = Arc::new(ScriptedHttp::new(vec![(
            "https://verifier.example/response".to_owned(),
            HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: br#"{"redirect_uri":"https://verifier.example/done"}"#.to_vec(),
            },
        )]));
        let ctx = test_context(host.clone(), http.clone());

        Oid4vpFlow
            .start_flow(&ctx, &start_params())
            .await
            .expect("the presentation flow completes");

        // The match ask carried the DCQL query and the verifier.
        let matches = host.matches.lock().expect("lock");
        assert_eq!(matches.len(), 1);
        assert!(matches[0].dcql_query.is_some());
        assert_eq!(matches[0].verifier.client_id, "https://verifier.example");
        assert!(matches[0].verifier.trusted);
        drop(matches);

        // The VP ask carried the audience, the nonce, both selections,
        // and the response endpoint; no thumbprint for direct_post.
        let vps = host.vps.lock().expect("lock");
        assert_eq!(vps.len(), 1);
        assert_eq!(vps[0].audience, "https://verifier.example");
        assert_eq!(vps[0].nonce, "nonce-vp-1");
        assert_eq!(vps[0].response_uri, "https://verifier.example/response");
        assert_eq!(vps[0].selections.len(), 2);
        assert_eq!(vps[0].selections[0].credential_query_id, "pid-query");
        assert_eq!(vps[0].verifier_jwk_thumbprint, "");
        drop(vps);

        // The submission: the vp_token restructured into the DCQL
        // object keyed by query id.
        let seen = http.seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        let body = String::from_utf8_lossy(&seen[0].body).into_owned();
        assert!(body.contains("vp_token="));
        let vp_token = body
            .strip_prefix("vp_token=")
            .and_then(|rest| rest.split('&').next())
            .unwrap_or_default();
        let decoded = crate::oid4vp::test_util::percent_decode(vp_token).into_bytes();
        let parsed: serde_json::Value =
            serde_json::from_slice(&decoded).expect("the restructured vp_token is JSON");
        assert_eq!(parsed["pid-query"], serde_json::json!(["token-pid"]));
        assert_eq!(parsed["degree-query"], serde_json::json!(["token-degree"]));
    }

    #[tokio::test]
    async fn an_empty_match_ends_the_flow_without_presenting() {
        struct EmptyMatchHost;
        #[async_trait::async_trait]
        impl Host for EmptyMatchHost {
            async fn request_sign(&self, _params: SignParams) -> Result<SignResult, HostError> {
                Err(HostError::Cannot("no".to_owned()))
            }
            async fn request_match(&self, _params: MatchParams) -> Result<MatchResult, HostError> {
                Ok(MatchResult {
                    selections: Vec::new(),
                })
            }
            async fn request_consent(
                &self,
                _params: ConsentParams,
            ) -> Result<ConsentResult, HostError> {
                Err(HostError::Cannot("never asked".to_owned()))
            }
            async fn request_tx_code(&self, _flow_id: &str) -> Result<String, HostError> {
                Err(HostError::Cannot("no".to_owned()))
            }
            async fn open_authorization(
                &self,
                _flow_id: &str,
                _url: &str,
            ) -> Result<(), HostError> {
                Ok(())
            }
            fn progress(&self, _flow_id: &str, _step: &str, _detail: Option<String>) {}
        }

        let http = Arc::new(ScriptedHttp::new(Vec::new()));
        let store = Arc::new(wmp_core::session::MemorySessionStore::new());
        let handler = Arc::new(wmp_core::sessionservice::SessionHandler::new(
            Arc::new(
                wmp_core::sessionservice::SessionService::new(
                    wmp_core::sessionservice::SessionServiceConfig {
                        store: Some(store.clone()),
                        entropy: Some(Arc::new(|bytes: &mut [u8]| {
                            for (i, b) in bytes.iter_mut().enumerate() {
                                *b = i as u8;
                            }
                            true
                        })),
                        ..wmp_core::sessionservice::SessionServiceConfig::default()
                    },
                )
                .unwrap_or_else(|_| panic!("session service")),
            ),
            Arc::new(|| 0),
        ));
        let peer = wmp_core::peer::PeerBuilder::new(handler)
            .session_store(store)
            .build();
        let ctx = FlowContext {
            flow_id: "flow-vp-1".to_owned(),
            flow_type: "oid4vp".to_owned(),
            session: None,
            ports: Arc::new(Ports {
                http: http.clone(),
                clock: Arc::new(FixedClock),
                rng: Arc::new(FakeRng),
                host: Arc::new(EmptyMatchHost),
                pdp: Arc::new(TrustedPdp),
                kv: Arc::new(MemKv(Mutex::new(rustc_hash::FxHashMap::default()))),
                telemetry: Arc::new(NoTelemetry),
            }),
            peer,
            request_context: wmp_core::context::RequestContext::default(),
        };

        Oid4vpFlow
            .start_flow(&ctx, &start_params())
            .await
            .expect("the empty match ends the flow, it is not an error");

        // The DCQL contract (OID4VP 1.0 §6.2, §6.4.2): the required
        // queries the wallet cannot satisfy answer with access_denied —
        // one error POST, no vp_token.
        let seen = http.seen.lock().expect("lock").clone();
        assert_eq!(seen.len(), 1, "exactly the access_denied submission");
        let body = String::from_utf8_lossy(&seen[0].body).into_owned();
        assert!(
            body.contains("error=access_denied"),
            "the access_denied error response: {body}"
        );
        assert!(!body.contains("vp_token="));
    }
}

#[cfg(test)]
mod untrusted_flow_tests {
    //! The untrusted-verifier refusal at the flow level: the typed -31006
    //! data (go-wmp's NewUntrustedVerifierData shape) rides the flow
    //! error — the class reason, the refused verifier, the PDP's detail,
    //! and the retryable flag. The ports are the presentation flow's own
    //! test fakes, reached through the parent module's re-exports.

    use super::presentation_flow_tests::{FakeRng, FixedClock, MemKv, NoTelemetry};
    use super::*;
    use crate::runtime::{FlowContext, FlowHandler};
    use crate::Ports;
    use engine_ports::{
        EvaluationRequest, EvaluationResponse, Host, HostError, HttpClient, HttpError, HttpRequest,
        HttpResponse, MatchParams, MatchResult, Pdp, PdpError, ResolveRequest, ResolveResponse,
        SignParams, SignResult,
    };
    use std::sync::{Arc, Mutex};

    /// The PDP that answers untrusted, with its reason.
    struct UntrustedPdp;

    #[async_trait::async_trait]
    impl Pdp for UntrustedPdp {
        async fn evaluate(
            &self,
            _request: EvaluationRequest,
        ) -> Result<EvaluationResponse, PdpError> {
            Ok(EvaluationResponse {
                trusted: false,
                decision: Some("not in the registry".to_owned()),
            })
        }
        async fn resolve(&self, _request: ResolveRequest) -> Result<ResolveResponse, PdpError> {
            Err(PdpError::NotImplemented)
        }
    }

    /// A host that answers nothing: the refusal happens before any ask.
    struct SilentHost;

    #[async_trait::async_trait]
    impl Host for SilentHost {
        async fn request_sign(&self, _params: SignParams) -> Result<SignResult, HostError> {
            Err(HostError::Cannot("silent".to_owned()))
        }
        async fn request_match(&self, _params: MatchParams) -> Result<MatchResult, HostError> {
            Err(HostError::Cannot("silent".to_owned()))
        }
        async fn request_consent(
            &self,
            _params: engine_ports::ConsentParams,
        ) -> Result<engine_ports::ConsentResult, HostError> {
            Err(HostError::Cannot("silent".to_owned()))
        }
        async fn request_tx_code(&self, _flow_id: &str) -> Result<String, HostError> {
            Err(HostError::Cannot("silent".to_owned()))
        }
        async fn open_authorization(&self, _flow_id: &str, _url: &str) -> Result<(), HostError> {
            Err(HostError::Cannot("silent".to_owned()))
        }
        fn progress(&self, _flow_id: &str, _step: &str, _detail: Option<String>) {}
    }

    struct EmptyHttp;

    #[async_trait::async_trait]
    impl HttpClient for EmptyHttp {
        async fn send(&self, _request: HttpRequest) -> Result<HttpResponse, HttpError> {
            Err(HttpError::Refused)
        }
    }

    #[tokio::test]
    async fn the_untrusted_verifier_refusal_carries_the_typed_flow_error_data() {
        let store = std::sync::Arc::new(wmp_core::session::MemorySessionStore::new());
        let _ = &store; // used by the session_store call below
        let peer = wmp_core::peer::PeerBuilder::new(Arc::new(
            wmp_core::sessionservice::SessionHandler::new(
                Arc::new(
                    wmp_core::sessionservice::SessionService::new(
                        wmp_core::sessionservice::SessionServiceConfig {
                            store: Some(store.clone()),
                            entropy: Some(Arc::new(|bytes: &mut [u8]| {
                                for (i, b) in bytes.iter_mut().enumerate() {
                                    *b = i as u8;
                                }
                                true
                            })),
                            ..wmp_core::sessionservice::SessionServiceConfig::default()
                        },
                    )
                    .unwrap_or_else(|_| panic!("session service")),
                ),
                Arc::new(|| 0),
            ),
        ))
        .session_store(store)
        .build();
        let ctx = FlowContext {
            flow_id: "flow-untrusted-1".to_owned(),
            flow_type: "oid4vp".to_owned(),
            session: None,
            ports: Arc::new(Ports {
                http: Arc::new(EmptyHttp),
                clock: Arc::new(FixedClock),
                rng: Arc::new(FakeRng),
                host: Arc::new(SilentHost),
                pdp: Arc::new(UntrustedPdp),
                kv: Arc::new(MemKv(Mutex::new(rustc_hash::FxHashMap::default()))),
                telemetry: Arc::new(NoTelemetry),
            }),
            peer,
            request_context: wmp_core::context::RequestContext::default(),
        };
        let flow = Oid4vpFlow;
        let params = super::presentation_flow_tests::start_params();
        let err = flow
            .start_flow(&ctx, &params)
            .await
            .expect_err("the untrusted verifier refuses");
        // The flow error: -31006 with the typed data.
        let HandlerError::Rpc(rpc) = &err else {
            panic!("the refusal is a flow error: {err:?}");
        };
        assert_eq!(rpc.code, wmp_core::error::ERR_FLOW_ERROR);
        let data: serde_json::Value = {
            let raw = rpc.data.as_ref().expect("the typed data rides the error");
            serde_json::from_str(raw.get()).expect("the data is JSON")
        };
        assert_eq!(
            data.get("reason").and_then(serde_json::Value::as_str),
            Some("untrusted_verifier"),
            "the class reason: {data}"
        );
        assert_eq!(
            data.get("verifier").and_then(serde_json::Value::as_str),
            Some("https://verifier.example"),
            "the refused verifier: {data}"
        );
        assert_eq!(
            data.get("detail").and_then(serde_json::Value::as_str),
            Some("not in the registry"),
            "the PDP's detail: {data}"
        );
        assert_eq!(
            data.get("retryable").and_then(serde_json::Value::as_bool),
            Some(false),
            "never retryable: {data}"
        );
    }
}
