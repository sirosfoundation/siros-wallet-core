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

        // The outer request URI, when the flow start carried one (the raw
        // params are the URL the QR code / link named). The §5 validations
        // compare the request object against it.
        let outer_request_uri = if raw_params.starts_with('{') {
            String::new()
        } else {
            raw_params.to_owned()
        };

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
        trust::evaluate_verifier_trust(
            ctx.pdp().as_ref(),
            &auth_req,
            client_metadata.as_ref(),
            &mut verifier,
        )
        .await
        .map_err(|err| flow_error(err.to_string()))?;

        let _ = ctx
            .progress(
                "trust_evaluated",
                &serde_json::json!({
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

        // Ask the host for credential selection: the match sub-flow.
        let match_result = ctx
            .host()
            .request_match(
                &params.flow_id,
                vec![engine_ports::MatchEntry {
                    credential_id: "cred-1".to_owned(),
                    display_name: "Credential 1".to_owned(),
                    credential_type: "sd-jwt".to_owned(),
                }],
            )
            .await
            .map_err(|err| flow_error(err.to_string()))?;

        let _ = ctx
            .progress(
                "credential_selected",
                &serde_json::json!({
                    "credential_id": match_result.selected_id,
                }),
            )
            .await;

        // Ask the host for consent.
        let consent = ctx
            .host()
            .request_consent(engine_ports::ConsentParams {
                flow_id: params.flow_id.clone(),
                purpose: auth_req.scope.clone(),
                requested_claims: vec![],
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
                "User declined",
            )
            .await;
            let _ = ctx.complete(&serde_json::json!({ "declined": true })).await;
            return Ok(FlowStartResult {
                wmp: wmp_core::types::Metadata::default(),
                flow_id: params.flow_id.clone(),
                flow_type: params.flow_type.clone(),
            });
        }

        // Build the VP signing input and ask the host to sign it.
        let vp_tbs = build_vp_signing_input(&auth_req, &match_result.selected_id);
        let sign_result = ctx
            .host()
            .request_sign(engine_ports::SignParams {
                flow_id: params.flow_id.clone(),
                to_sign: vp_tbs.into_bytes(),
                key_id: None,
                algorithm: "ES256".to_owned(),
            })
            .await
            .map_err(|err| flow_error(err.to_string()))?;

        let vp_token = String::from_utf8_lossy(&sign_result.signature).into_owned();

        // The DCQL vp_token assembly (OID4VP §8.1): a newline-separated
        // answer restructures into the object keyed by credential query
        // id; a host that returned a JSON object passes through.
        let vp_token = if auth_req.dcql_query.is_some() {
            let selections = vec![dcql::ConsentSelection {
                credential_query_id: match_result.query_id.clone().unwrap_or_default(),
                credential_id: match_result.selected_id.clone(),
            }];
            dcql::build_dcql_vp_token(&vp_token, &selections)
                .map_err(|err| flow_error(err.to_string()))?
        } else {
            vp_token
        };

        // Submit the response per the request's response mode. The
        // Clock port supplies the JARM `iat`/`exp`.
        let _ = response::submit_response(
            ctx.http().as_ref(),
            &auth_req,
            &vp_token,
            ctx.clock().now_unix(),
        )
        .await
        .map_err(|err| flow_error(err.to_string()))?;

        let _ = ctx
            .complete(&serde_json::json!({
                "presented": true,
                "credential_id": match_result.selected_id,
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

/// Builds the VP signing input: the audience, nonce, response URI, and the
/// selected credential. The host signs this as the VP token.
fn build_vp_signing_input(auth_req: &types::AuthorizationRequest, credential_id: &str) -> String {
    let audience = if !auth_req.client_id.is_empty() {
        auth_req.client_id.clone()
    } else {
        auth_req.redirect_uri.clone()
    };
    format!(
        "{}|{}|{}|{}",
        audience, auth_req.nonce, auth_req.response_uri, credential_id
    )
}
