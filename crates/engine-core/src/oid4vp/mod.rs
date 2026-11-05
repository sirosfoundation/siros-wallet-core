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
                    ctx.clock().now_unix(),
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
