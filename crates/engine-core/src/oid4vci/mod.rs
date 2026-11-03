//! The OID4VCI flow family: offer parsing, issuer metadata resolution, AS
//! metadata discovery — S1's slice of the issuance flow, built on the
//! `FlowHandler` seam the echo flow proved.

pub mod as_metadata;
pub mod issuer;
pub mod offer;
pub mod types;

use wmp_core::handler::HandlerError;
use wmp_core::methods::*;

use crate::runtime::{FlowContext, FlowHandler};
use types::MetadataType;

/// The OID4VCI flow handler: parses the offer from the flow start's
/// params, resolves the issuer metadata, discovers the AS metadata, and
/// reports the result (or the refusal). This is S1; S2 adds the token
/// exchange and the credential request on top of the same handler.
pub struct Oid4vciFlow;

#[async_trait::async_trait]
impl FlowHandler for Oid4vciFlow {
    fn flow_types(&self) -> Vec<String> {
        vec!["oid4vci".to_owned()]
    }

    fn required_capability(&self, _flow_type: &str) -> String {
        // The `flows` capability, per the OpenID4x profile.
        "flows".to_owned()
    }

    async fn start_flow(
        &self,
        ctx: &FlowContext,
        params: &FlowStartParams,
    ) -> Result<FlowStartResult, HandlerError> {
        // The flow start's params carry the credential offer (by value,
        // by reference, or by URI scheme) or the `credential_issuer` URL.
        let offer_params = params
            .params
            .as_deref()
            .map(|raw| raw.get())
            .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
            .unwrap_or(serde_json::Value::Null);

        // Step 1: parse the offer (or the issuer URL when there's no offer).
        let offer = offer::parse_offer(ctx.http().as_ref(), &offer_params)
            .await
            .map_err(|err| {
                wmp_core::error::RpcError::new(
                    wmp_core::error::ERR_FLOW_ERROR,
                    Some(serde_json::json!({ "reason": err.to_string() })),
                )
            })?;

        // Report progress: the offer parsed.
        let _ = ctx
            .progress(
                "offer_parsed",
                &serde_json::json!({
                    "credential_issuer": offer.credential_issuer,
                    "credential_configuration_ids": offer.credential_configuration_ids,
                }),
            )
            .await;

        // Step 2: resolve the issuer metadata.
        // The metadata_type policy from the engine config (the default
        // is prefer-signed). The full config plumbing arrives with S2.
        let metadata_type = MetadataType::PreferSigned;

        let issuer_metadata = issuer::resolve_issuer_metadata(
            ctx.http().as_ref(),
            &offer.credential_issuer,
            metadata_type,
            false,
        )
        .await
        .map_err(|err| {
            wmp_core::error::RpcError::new(
                wmp_core::error::ERR_FLOW_ERROR,
                Some(serde_json::json!({ "reason": err.to_string() })),
            )
        })?;

        // Report progress: the metadata resolved.
        let _ = ctx
            .progress(
                "metadata_resolved",
                &serde_json::json!({
                    "credential_issuer": issuer_metadata.credential_issuer,
                    "is_signed": issuer_metadata.is_signed,
                }),
            )
            .await;

        // Step 3: discover the AS metadata for the first authorization
        // server (or the issuer itself when it has none).
        let as_url = issuer_metadata
            .authorization_servers
            .first()
            .cloned()
            .unwrap_or_else(|| offer.credential_issuer.clone());

        let as_metadata = as_metadata::discover_as_metadata(ctx.http().as_ref(), &as_url, false)
            .await
            .map_err(|err| {
                wmp_core::error::RpcError::new(
                    wmp_core::error::ERR_FLOW_ERROR,
                    Some(serde_json::json!({ "reason": err.to_string() })),
                )
            })?;

        // Report progress: the AS discovered.
        let _ = ctx
            .progress(
                "as_discovered",
                &serde_json::json!({
                    "issuer": as_metadata.issuer,
                    "token_endpoint": as_metadata.token_endpoint,
                }),
            )
            .await;

        // S1 ends here. The flow started, the offer parsed, the metadata
        // resolved, the AS discovered. S2 continues with the token
        // exchange and the credential request.
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
        // S2 adds the actions (tx_code, authorization_complete).
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
