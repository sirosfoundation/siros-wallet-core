//! The OpenID4VP flow family: request parsing, verifier trust, credential
//! selection, transaction data, VP signing, and response submission — S4's
//! presentation flow, built on the same `FlowHandler` seam.

pub mod consent;
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
                // The verifier's client metadata, verbatim — the wallet's
                // planner reads `vp_formats_supported.zkp_req`'s circuit lists
                // for the plan's system_filter, and the consent reads
                // client_name/logo_uri. Found on-device: without it the plan
                // carried no filter and every zkp_req ask refused at
                // step=CIRCUIT.
                client_metadata: auth_req.client_metadata.clone(),
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
            // The refusal step the app observes on either channel.
            let _ = ctx
                .progress(
                    "no_matching_credential",
                    &serde_json::json!({
                        "requested": dcql::requested_credential_types(auth_req.dcql_query.as_ref()),
                        "unsatisfied": unsatisfied,
                    }),
                )
                .await;
            let mut error_redirect: Option<String> = None;
            if !unsatisfied.is_empty() || auth_req.dcql_query.is_some() {
                // The Digital Credentials API channel: the error
                // returns through the browser like the success answer —
                // the completion carries the DigitalCredential's error
                // data the host hands to the verifier page (§8.4).
                if auth_req.response_mode.is_dc_api() {
                    let _ = ctx
                        .complete(&serde_json::json!({
                            "matched": false,
                            "refused": true,
                            "dc_api_response": {
                                "error": "access_denied",
                                "error_description": "The wallet did not fulfil the request",
                            },
                        }))
                        .await;
                    return Ok(FlowStartResult {
                        wmp: wmp_core::types::Metadata::default(),
                        flow_id: params.flow_id.clone(),
                        flow_type: params.flow_type.clone(),
                    });
                }
                // The error answer, captured: the direct modes POST it (the
                // Go engine's verifierRefusedDescription - the verifier
                // must not tell a refusal from an empty wallet apart);
                // the redirect modes BUILD the return URL instead, and that
                // URL rides the completion as `redirect_uri` - the wallet
                // UI's back-to-verifier link (found on-device: the no-match
                // refusal left the user stranded in the wallet while the
                // verifier showed "wallet declined"). Absent on direct_post
                // errors - the POST's 200 answer carries any redirect the
                // wallet would need separately, and a verifier that wants
                // no return-link simply omits it.
                let submitted = response::submit_error_response(
                    ctx.http().as_ref(),
                    &auth_req,
                    "access_denied",
                    "The wallet did not fulfil the request",
                    ctx.clock().now_unix(),
                )
                .await;
                error_redirect = submitted.ok().filter(|r| r.starts_with("http"));
            }
            let _ = ctx
                .complete(&serde_json::json!({
                    "matched": false,
                    "refused": true,
                    "redirect_uri": error_redirect,
                }))
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

        // ── The consent policy (#525, the Go consentPolicy.Decide):
        // the host's answer is vetted against the query it was sent
        // before anything is signed. The Go engine vets the one
        // answer its single ask carries; this core's match and
        // consent asks are two, so the vetting sits on the match
        // answer — a refused answer never reaches the consent UI.
        // An `enforce` deployment refuses the presentation: the
        // verifier is answered `access_denied`, as a decline is, and
        // the flow ends with the refusal's reason class. `warn`
        // records the violation (telemetry: the reason class and the
        // query id alone) and proceeds; `off` compares nothing. A
        // query that cannot be interpreted is a violation, never a
        // pass.
        if let Some(violation) =
            consent::vet(ctx, auth_req.dcql_query.as_ref(), &match_result.selections).await
        {
            let _ = response::submit_error_response(
                ctx.http().as_ref(),
                &auth_req,
                "access_denied",
                // The same description as every refusal: the verifier
                // must not tell a refused consent from a decline or an
                // empty wallet apart.
                "The wallet did not fulfil the request",
                ctx.clock().now_unix(),
            )
            .await;
            let _ = ctx
                .complete(&serde_json::json!({
                    "refused": true,
                    "reason": violation.reason,
                }))
                .await;
            return Ok(FlowStartResult {
                wmp: wmp_core::types::Metadata::default(),
                flow_id: params.flow_id.clone(),
                flow_type: params.flow_type.clone(),
            });
        }

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
            // The decline: the Digital Credentials API channel answers
            // through the browser (the error data rides the
            // completion, §8.4); the redirect channel's is a plain
            // form POST, never encrypted (P0.6).
            if auth_req.response_mode.is_dc_api() {
                let _ = ctx
                    .complete(&serde_json::json!({
                        "declined": true,
                        "dc_api_response": {
                            "error": "access_denied",
                            "error_description": "The wallet did not fulfil the request",
                        },
                    }))
                    .await;
                return Ok(FlowStartResult {
                    wmp: wmp_core::types::Metadata::default(),
                    flow_id: params.flow_id.clone(),
                    flow_type: params.flow_type.clone(),
                });
            }
            let _ = response::submit_error_response(
                ctx.http().as_ref(),
                &auth_req,
                "access_denied",
                // The same description as the empty-match refusal: the
                // verifier must not tell a decline from an empty wallet
                // apart (the Go engine's verifierRefusedDescription).
                "The wallet did not fulfil the request",
                ctx.clock().now_unix(),
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
        let vp_result = match ctx
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
                // The Digital Credentials API channel's actual origin:
                // the transport's caller, validated against the
                // expected_origins at the parse (empty otherwise).
                origin: auth_req.dc_api_origin.clone(),
                // The transport's selection handle, unchanged (WMP
                // OpenID4x 3.2.3.1): the answer's correlation rides
                // back so the transport's ask matches its answer.
                selection_handle: match_result.handle.clone(),
                // The request as the engine verified it: the wallet's ZK
                // policy gate (signed + encrypted response), the JARM aud
                // (the certificate's client_id, never the audience), the
                // response mode. Absent for a request the engine did not
                // verify — the wallet's policy then refuses, which is the
                // correct answer for an unauthenticated request.
                verified_request: if !auth_req.client_id.is_empty() {
                    Some(engine_ports::VpVerifiedRequest {
                        client_id: auth_req.client_id.clone(),
                        client_id_scheme: auth_req.client_id_scheme.name().to_owned(),
                        response_mode: auth_req.response_mode.as_str().to_owned(),
                        response_uri: auth_req.response_uri.clone(),
                        // The parser refuses a request object whose
                        // signature does not verify (RequestObjectSignature),
                        // so a present request JWT is a VERIFIED one — and
                        // the DID schemes verify against resolved keys, not
                        // an x5c chain, so the x5c is not the truth source.
                        signed: auth_req.request_jwt.is_some(),
                        signature_verification: if auth_req.request_jwt.is_some() {
                            // The engine verifies synchronously at parse; it
                            // never defers.
                            "verified".to_owned()
                        } else {
                            "none".to_owned()
                        },
                        request_jwt: auth_req.request_jwt.clone(),
                    })
                } else {
                    None
                },
                // The response encryption parameters: the SAME key and
                // algorithms the engine's own JARM submission selects —
                // the wallet's ZK policy gate requires the member for
                // direct_post.jwt (the "encrypted response" leg), and its
                // transcript thumbprint cross-checks the jwk against the
                // verifier_jwk_thumbprint above (both derive from this one
                // selection, so they always agree). Found on-device: the
                // first cut read the request object's top-level `jwk`
                // member, which the nym_auth request does not carry (its
                // key lives in client_metadata.jwks), so the member left
                // the engine empty and the wallet refused at
                // step=response-not-encrypted.
                response_encryption: (|| {
                    let metadata = auth_req.client_metadata.as_ref()?;
                    let jwk = jarm::select_verifier_jwk(metadata).ok()?;
                    let (alg, enc) = jarm::resolve_algorithms(Some(metadata), &jwk).ok()?;
                    Some(engine_ports::VpResponseEncryption {
                        jwk: serde_json::to_value(&jwk).ok()?,
                        alg: alg.as_str().to_owned(),
                        enc: enc.as_str().to_owned(),
                    })
                })()
                .or_else(|| {
                    // The request object's own top-level `jwk` member, the
                    // pre-spec shape: its alg/enc when it carries them, the
                    // spec's defaults otherwise.
                    auth_req.verifier_jwk.clone().map(|jwk| {
                        let alg = jwk
                            .get("alg")
                            .and_then(|v| v.as_str())
                            .unwrap_or("RSA-OAEP")
                            .to_owned();
                        let enc = jwk
                            .get("enc")
                            .and_then(|v| v.as_str())
                            .unwrap_or("A256GCM")
                            .to_owned();
                        engine_ports::VpResponseEncryption { jwk, alg, enc }
                    })
                }),
            })
            .await
        {
            Ok(result) => result,
            // The user's decline at the sign stage (#472): the verifier
            // is answered `access_denied` at once — never left waiting
            // out its session — and the client gets the same decline
            // error as a consent-stage refusal, with the verifier's
            // redirect if it answered one. The wallet's reason never
            // reaches the verifier (OpenID4x 3.2.6).
            Err(engine_ports::HostError::Declined) => {
                return refuse_verifier(ctx, &auth_req, "access_denied").await;
            }
            Err(other) => return Err(flow_error(other.to_string()).into()),
        };

        // The host's sign refusal (the Go `sign_response.error_code`,
        // #472): `SIGN_REFUSED` answers the verifier `access_denied` —
        // the same public shape as every refusal; a transaction-type
        // refusal answers `invalid_transaction_data` instead, so the
        // verifier is not left waiting on a form it would reject.
        if let Some(refusal) = vp_result.refusal {
            return match refusal.code.as_str() {
                "UNSUPPORTED_TRANSACTION_DATA" => {
                    refuse_verifier(ctx, &auth_req, "invalid_transaction_data").await
                }
                // SIGN_REFUSED and anything else the host allowlisted:
                // the verifier is told access_denied, nothing more.
                _ => refuse_verifier(ctx, &auth_req, "access_denied").await,
            };
        }

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

        // The Digital Credentials API channel (OpenID4VP 1.0 §8.4): the
        // response never POSTs back from the wallet — the host hands it
        // to the browser (the API's promise), and the verifier's page
        // receives it. `dc_api` answers with the plain response
        // object; `dc_api.jwt` with the JWE-encrypted one.
        if auth_req.response_mode.is_dc_api() {
            let dc_api_response = match auth_req.response_mode {
                types::ResponseMode::DcApiJwt => {
                    let jwe = jarm::build_dc_api_jwe_response(
                        &auth_req,
                        &vp_token,
                        ctx.clock().now_unix(),
                    )
                    .map_err(|err| flow_error(err.to_string()))?;
                    serde_json::json!({ "response": jwe })
                }
                _ => {
                    let mut response = serde_json::Map::new();
                    response.insert(
                        "vp_token".to_owned(),
                        serde_json::Value::String(vp_token.clone()),
                    );
                    if !auth_req.state.is_empty() {
                        response.insert(
                            "state".to_owned(),
                            serde_json::Value::String(auth_req.state.clone()),
                        );
                    }
                    serde_json::Value::Object(response)
                }
            };
            let _ = ctx
                .progress(
                    "response_returned",
                    &serde_json::json!({ "channel": auth_req.response_mode.as_str() }),
                )
                .await;
            let _ = ctx
                .complete(&serde_json::json!({
                    "presented": true,
                    "credential_ids": match_result
                        .selections
                        .iter()
                        .map(|s| s.credential_id.clone())
                        .collect::<Vec<_>>(),
                    // The DigitalCredential's data the host returns
                    // through the browser API; the harness hands it to
                    // the verifier page's submit URL.
                    "dc_api_response": dc_api_response,
                }))
                .await;
            return Ok(FlowStartResult {
                wmp: wmp_core::types::Metadata::default(),
                flow_id: params.flow_id.clone(),
                flow_type: params.flow_type.clone(),
            });
        }

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

/// Refuses the verifier at the sign stage (#472, OpenID4x 3.2.6): the
/// verifier is answered `error_code` at once — the same public shape as
/// every refusal, so it cannot tell a sign refusal from a consent decline
/// or an empty wallet — and the client gets the decline completion with
/// the verifier's redirect, if it answered one.
///
/// The wallet's reason never crosses: the engine knows only the
/// allowlisted code (`SIGN_REFUSED`, `UNSUPPORTED_TRANSACTION_DATA`), and
/// the description is the shared refusal wording, never what the wallet
/// said.
async fn refuse_verifier(
    ctx: &FlowContext,
    auth_req: &types::AuthorizationRequest,
    error_code: &str,
) -> Result<FlowStartResult, HandlerError> {
    // The Digital Credentials API channel: the error returns through
    // the browser (the error data rides the completion, §8.4) — no
    // HTTP POST from the wallet.
    if auth_req.response_mode.is_dc_api() {
        let _ = ctx
            .complete(&serde_json::json!({
                "declined": true,
                "dc_api_response": {
                    "error": error_code,
                    "error_description": "The wallet did not fulfil the request",
                },
            }))
            .await;
        return Ok(FlowStartResult {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: ctx.flow_id.clone(),
            flow_type: ctx.flow_type.clone(),
        });
    }

    let redirect = response::submit_error_response(
        ctx.http().as_ref(),
        auth_req,
        error_code,
        // The same description as every refusal: the verifier must not
        // tell a sign refusal from a decline or an empty wallet apart
        // (the Go engine's verifierRefusedDescription).
        "The wallet did not fulfil the request",
        ctx.clock().now_unix(),
    )
    .await;

    // The completion: the decline, with the verifier's redirect if it
    // answered one (the Go engine's details.redirect_uri).
    let mut completion = serde_json::json!({ "declined": true });
    if let Ok(uri) = redirect {
        if !uri.is_empty() {
            if let Some(object) = completion.as_object_mut() {
                object.insert("redirect_uri".to_owned(), serde_json::Value::String(uri));
            }
        }
    }
    let _ = ctx.complete(&completion).await;

    Ok(FlowStartResult {
        wmp: wmp_core::types::Metadata::default(),
        flow_id: ctx.flow_id.clone(),
        flow_type: ctx.flow_type.clone(),
    })
}
