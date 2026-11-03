//! The OID4VCI flow family: offer parsing, issuer metadata, AS metadata,
//! the token exchange, and the credential request — S1 + S2's slice of the
//! issuance flow, built on the `FlowHandler` seam the echo flow proved.

pub mod as_metadata;
pub mod credential;
pub mod issuer;
pub mod offer;
pub mod token;
pub mod types;

use wmp_core::handler::HandlerError;
use wmp_core::methods::*;

use crate::runtime::{FlowContext, FlowHandler};
use types::MetadataType;

/// The OID4VCI flow handler: the full S1+S2 issuance flow — parse the
/// offer, resolve the issuer metadata, discover the AS, exchange the
/// pre-authorized code for a token, request the credential with the
/// host-signed proof, and report the result.
pub struct Oid4vciFlow;

#[async_trait::async_trait]
impl FlowHandler for Oid4vciFlow {
    fn flow_types(&self) -> Vec<String> {
        vec!["oid4vci".to_owned()]
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

        // ── S1: parse the offer ───────────────────────────────────────────
        let offer_params = params
            .params
            .as_deref()
            .map(|raw| raw.get())
            .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
            .unwrap_or(serde_json::Value::Null);

        let offer = offer::parse_offer(ctx.http().as_ref(), &offer_params)
            .await
            .map_err(|err| flow_error(err.to_string()))?;

        let _ = ctx
            .progress(
                "offer_parsed",
                &serde_json::json!({
                    "credential_issuer": offer.credential_issuer,
                    "credential_configuration_ids": offer.credential_configuration_ids,
                }),
            )
            .await;

        // ── S1: resolve the issuer metadata ──────────────────────────────
        let metadata_type = MetadataType::PreferSigned;
        let issuer_metadata = issuer::resolve_issuer_metadata(
            ctx.http().as_ref(),
            &offer.credential_issuer,
            metadata_type,
            false,
        )
        .await
        .map_err(|err| flow_error(err.to_string()))?;

        let _ = ctx
            .progress(
                "metadata_resolved",
                &serde_json::json!({
                    "credential_issuer": issuer_metadata.credential_issuer,
                    "is_signed": issuer_metadata.is_signed,
                }),
            )
            .await;

        // ── S1: discover the AS metadata ────────────────────────────────
        let as_url = issuer_metadata
            .authorization_servers
            .first()
            .cloned()
            .unwrap_or_else(|| offer.credential_issuer.clone());

        let as_metadata = as_metadata::discover_as_metadata(ctx.http().as_ref(), &as_url, false)
            .await
            .map_err(|err| flow_error(err.to_string()))?;

        let _ = ctx
            .progress(
                "as_discovered",
                &serde_json::json!({
                    "issuer": as_metadata.issuer,
                    "token_endpoint": as_metadata.token_endpoint,
                }),
            )
            .await;

        // ── S2: exchange the pre-authorized code for a token ─────────────
        // The grants in the offer say whether this is a pre-authorized_code
        // flow; if it is, the tx_code is asked of the host.
        let pre_auth = offer
            .grants
            .get("urn:ietf:params:oauth:grant-type:pre-authorized_code")
            .cloned();

        let (token, credential) = if let Some(grant) = pre_auth {
            let pre_auth_code = grant
                .get("pre-authorized_code")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            let tx_code_required = grant.get("tx_code").map(|v| !v.is_null()).unwrap_or(false);

            let token = token::exchange_pre_authorized_code(
                ctx.http().as_ref(),
                ctx.host().as_ref(),
                &as_metadata,
                &pre_auth_code,
                tx_code_required,
            )
            .await
            .map_err(|err| flow_error(err.to_string()))?;

            let _ = ctx
                .progress(
                    "token_received",
                    &serde_json::json!({
                        "token_type": token.token_type,
                    }),
                )
                .await;

            // ── S2: request the credential with the host-signed proof ──
            let configuration_id = offer
                .credential_configuration_ids
                .first()
                .cloned()
                .unwrap_or_default();

            let credential = credential::request_credential(
                ctx.http().as_ref(),
                ctx.host().as_ref(),
                &issuer_metadata,
                &token,
                &configuration_id,
                token.nonce.as_deref().or(token.c_nonce.as_deref()),
            )
            .await
            .map_err(|err| flow_error(err.to_string()))?;

            let _ = ctx
                .progress(
                    "credential_received",
                    &serde_json::json!({
                        "has_credential": credential.credential.is_some(),
                        "transaction_id": credential.transaction_id,
                    }),
                )
                .await;

            (Some(token), Some(credential))
        } else {
            // Not a pre-authorized code grant: S1 only (the metadata
            // resolved; S2's authorization-code grant is the S4 stretch).
            (None, None)
        };

        // Report the flow completion with the credential result.
        let _ = ctx
            .complete(&serde_json::json!({
                "credential": credential.as_ref()
                    .and_then(|c| c.credential.clone())
                    .unwrap_or_default(),
                "deferred": credential.as_ref()
                    .and_then(|c| c.transaction_id.clone())
                    .is_some(),
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
