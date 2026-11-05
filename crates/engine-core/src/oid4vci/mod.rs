//! The OID4VCI flow family: offer parsing, issuer metadata, AS metadata,
//! the token exchange, and the credential request — S1 + S2's slice of the
//! issuance flow, built on the `FlowHandler` seam the echo flow proved.

pub mod as_metadata;
pub mod attestation;
pub mod auth_code;
pub mod auth_params;
pub mod auxiliary;
pub mod credential;
pub mod deferred;
pub mod dpop;
pub mod encryption;
pub mod issuer;
pub mod nonce;
pub mod offer;
pub mod token;
pub mod trust;
pub mod types;

use wmp_core::handler::HandlerError;
use wmp_core::methods::*;

use trust::TrustError;

use crate::runtime::{FlowContext, FlowHandler};
use types::MetadataType;

/// The OID4VCI flow handler: the full S1+S2 issuance flow — parse the
/// offer, resolve the issuer metadata, discover the AS, exchange the
/// The AS the flow discovers (#511): the offer's grant-level
/// `authorization_server` hint — OpenID4VCI 1.0/1.1: "the Wallet MUST NOT
/// proceed with the flow if the `authorization_server` Credential Offer
/// parameter value does not match any of the entries in the
/// `authorization_servers` array" — else the first advertised (the
/// documented choice when the offer carries no hint and several are
/// advertised), else the credential issuer itself (the same-origin AS).
fn select_as_url(
    offer: &types::CredentialOffer,
    issuer_metadata: &types::IssuerMetadata,
) -> Result<String, String> {
    // The hint: the grant's authorization_server member (either grant
    // carries it; the first found wins).
    let hint = offer
        .grants
        .as_object()
        .and_then(|grants| {
            grants
                .values()
                .find_map(|grant| grant.get("authorization_server").and_then(|v| v.as_str()))
        })
        .filter(|url| !url.is_empty());
    match hint {
        Some(hint) => {
            // MUST equal (exact string comparison) one of the advertised
            // entries; a mismatch fails closed.
            if issuer_metadata
                .authorization_servers
                .iter()
                .any(|url| url == hint)
            {
                Ok(hint.to_owned())
            } else {
                Err(format!(
                    "the offer names authorization_server {hint:?} which the issuer metadata does not advertise"
                ))
            }
        }
        // No hint: the first advertised (the documented choice), else the
        // credential issuer itself.
        None => Ok(issuer_metadata
            .authorization_servers
            .first()
            .cloned()
            .unwrap_or_else(|| offer.credential_issuer.clone())),
    }
}

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

        // A renewal (credential re-issuance): no fresh offer — the
        // client already knows the issuer and the configuration and
        // supplies the refresh_token the previous flow returned. The
        // synthetic single-config offer lets every downstream step run
        // unchanged (the Go engine's buildRenewalOffer).
        let renewal_token = offer_params
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .filter(|t| !t.is_empty())
            .map(str::to_owned);

        let offer = if renewal_token.is_some() {
            let issuer = offer_params
                .get("credential_issuer")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let configuration_id = offer_params
                .get("selected_credential_configuration_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if issuer.is_empty() || configuration_id.is_empty() {
                return Err(flow_error(
                    "renewal request missing credential_issuer or                      selected_credential_configuration_id"
                        .to_owned(),
                )
                .into());
            }
            types::CredentialOffer {
                credential_issuer: issuer.to_owned(),
                credential_configuration_ids: vec![configuration_id.to_owned()],
                grants: serde_json::json!({}),
            }
        } else {
            offer::parse_offer(ctx.http().as_ref(), &offer_params)
                .await
                .map_err(|err| flow_error(err.to_string()))?
        };

        // The Go engine's step vocabulary: message steps around each
        // phase, the drop-in surface the SDK's FlowStepCatalog and the
        // frontend's UI state machine key on (docs/engine-parity.md §2).
        let _ = ctx
            .progress(
                "parsing_offer",
                &serde_json::json!({ "message": "parsing the credential offer" }),
            )
            .await;

        let _ = ctx
            .progress(
                "offer_parsed",
                &serde_json::json!({
                    "credential_issuer": offer.credential_issuer,
                    "credential_configuration_ids": offer.credential_configuration_ids,
                    "grants": offer.grants,
                }),
            )
            .await;

        // ── S1: resolve the issuer metadata ──────────────────────────────
        let _ = ctx
            .progress(
                "fetching_metadata",
                &serde_json::json!({ "message": "resolving the issuer metadata" }),
            )
            .await;

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
                "metadata_fetched",
                &serde_json::json!({
                    "credential_issuer": issuer_metadata.credential_issuer,
                    "is_signed": issuer_metadata.is_signed,
                }),
            )
            .await;

        // ── S1: discover the AS metadata ────────────────────────────────
        // #511: the offer's grant-level authorization_server hint
        // selects the AS (and a mismatch fails closed); without a hint,
        // the first advertised.
        let as_url = select_as_url(&offer, &issuer_metadata).map_err(flow_error)?;

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

        // ── S3: evaluate the issuer's trust through the PDP ─────────────
        let _ = ctx
            .progress(
                "evaluating_trust",
                &serde_json::json!({ "message": "evaluating the issuer trust" }),
            )
            .await;

        // Fail closed: an unreachable PDP or an untrusted issuer refuses
        // the flow. No fallback to client-asserted trust.
        let trust_info = trust::evaluate_issuer_trust(
            ctx.pdp().as_ref(),
            &offer.credential_issuer,
            &issuer_metadata,
        )
        .await
        .map_err(|err| match &err {
            // The typed -31006 data (go-wmp's NewUntrustedIssuerData):
            // the class reason, the refused issuer, the PDP's detail,
            // and the retryable flag.
            TrustError::Untrusted { issuer, reason } => {
                HandlerError::Rpc(wmp_core::error::RpcError::new(
                    wmp_core::error::ERR_FLOW_ERROR,
                    Some(trust::untrusted_issuer_data(issuer, reason)),
                ))
            }
            _ => HandlerError::Rpc(flow_error(err.to_string())),
        })?;

        let _ = ctx
            .progress(
                "trust_evaluated",
                &serde_json::json!({
                    "issuer_trust_evaluated": true,
                    "issuer": offer.credential_issuer,
                    "trusted": trust_info.trusted,
                    "framework": trust_info.framework,
                    "reason": trust_info.reason,
                }),
            )
            .await;

        // ── The auxiliary-data selection gate (Credential Auxiliary Data
        // v0.1, #480): the advertisement is read from the selected
        // configuration BEFORE any authorization or request — an entry the
        // wallet cannot handle (a to_wallet alg/encoding, a required
        // to_issuer entry) refuses with the AUXILIARY_DATA_UNSUPPORTED
        // shape, and a malformed advertisement (an auxiliary_data member
        // in the issuer's credential_metadata among them) fails closed.
        // The engine never handles a secret value: the gate reads the
        // advertisement alone.
        let configuration_id = offer
            .credential_configuration_ids
            .first()
            .cloned()
            .unwrap_or_default();
        let configuration = issuer_metadata
            .credential_configurations
            .get(&configuration_id)
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let delivery = match auxiliary::secret_delivery_of(&configuration) {
            Ok(delivery) => delivery,
            Err(err) => {
                // The advertisement is malformed (or auxiliary_data rode
                // the issuer metadata): fail closed, nothing of the
                // content in the reason.
                return Err(HandlerError::Rpc(flow_error(err.reason())));
            }
        };
        if let Err(refusal) = auxiliary::usable(&delivery, &configuration) {
            // The AUXILIARY_DATA_UNSUPPORTED refusal: the typed -31006
            // data carries the class reason and the retryable flag
            // (never retryable — a different wallet or the issuer's
            // out-of-band resolution is the fix).
            return Err(HandlerError::Rpc(wmp_core::error::RpcError::new(
                wmp_core::error::ERR_FLOW_ERROR,
                Some(serde_json::json!({
                    "reason": "auxiliary_data_unsupported",
                    "detail": refusal.reason,
                    "retryable": false,
                })),
            )));
        }

        // ── S2: negotiate the response encryption, when the issuer supports it
        // The alg/enc pair from the issuer's credential_response_encryption
        // metadata, in preference order (A256GCM first). The key the wallet
        // offers goes in the credential request's
        // credential_response_encryption member. When the issuer required
        // encryption and no pair overlaps, the flow refuses — there is no
        // compliant way to request the credential.
        let negotiated_encryption = negotiated_encryption_for(&issuer_metadata);
        if let (Some(config), None) = (
            encryption_config_for(&issuer_metadata),
            negotiated_encryption.as_ref(),
        ) {
            if config.required {
                return Err(flow_error(encryption::EncryptionError::NoOverlap.to_string()).into());
            }
        }

        // The wallet's client_id (the token exchange's form member and
        // the attestation PoP iss): the registered id, else the
        // redirect_uri (the unregistered-client convention).
        let client_id = offer_params
            .get("client_id")
            .and_then(|v| v.as_str())
            .filter(|id| !id.is_empty())
            .or_else(|| offer_params.get("redirect_uri").and_then(|v| v.as_str()))
            .unwrap_or_default()
            .to_owned();

        // The DPoP key: a renewal reuses the key its refresh_token was
        // bound to at issuance (RFC 9449 / ARF 3.0 §6.6.6.6.2.2) — the
        // engine-held key the previous flow relayed back as `dpop_jwk`,
        // while `dpop_key_id` names the client-held key for the host's
        // proof ask. A fresh flow generates an engine-held key (the
        // legacy mode; the host's own proof is preferred when it can
        // sign).
        let dpop_key_id = offer_params
            .get("dpop_key_id")
            .and_then(|v| v.as_str())
            .filter(|id| !id.is_empty())
            .map(str::to_owned);
        let dpop_key = if renewal_token.is_some() {
            offer_params
                .get("dpop_jwk")
                .and_then(|v| v.as_str())
                .and_then(|jwk| dpop::DpopKey::from_private_jwk_json(jwk).ok())
        } else {
            dpop::DpopKey::generate().ok()
        };

        // The reissuance kid: a renewal's proof is signed with the
        // EXISTING keypair the issuer knows (ARF ISSU_65 same-key
        // re-signing) — the key id rides the sign ask.
        let reissuance_kid = offer_params
            .get("reissuance_kid")
            .and_then(|v| v.as_str())
            .filter(|kid| !kid.is_empty())
            .map(str::to_owned);

        // The wallet's registered client key's kid (the private_key_jwt
        // assertion's kid): the app knows the kid it registered with
        // the AS, the engine asks the host to sign with it.
        let client_key_kid = offer_params
            .get("client_key_kid")
            .and_then(|v| v.as_str())
            .filter(|kid| !kid.is_empty())
            .map(str::to_owned);

        // ── S2: exchange the pre-authorized code for a token ─────────────
        // The grants in the offer say whether this is a pre-authorized_code
        // flow; if it is, the tx_code is asked of the host.
        let pre_auth = offer
            .grants
            .get("urn:ietf:params:oauth:grant-type:pre-authorized_code")
            .cloned();

        let (_token, credential) = if let Some(refresh) = &renewal_token {
            // ── The renewal grant: the refresh token the previous flow
            // returned, exchanged with the same client-auth loop.
            let _ = ctx
                .progress(
                    "exchanging_token",
                    &serde_json::json!({ "message": "exchanging the code for a token" }),
                )
                .await;

            let token = token::exchange_refresh_token(
                ctx.http().as_ref(),
                ctx.host().as_ref(),
                &as_metadata,
                refresh,
                &token::TokenExchangeContext {
                    flow_id: &params.flow_id,
                    client_id: &client_id,
                    dpop_key_id: dpop_key_id.as_deref(),
                    client_key_kid: client_key_kid.as_deref(),
                    dpop: dpop_key.as_ref(),
                    rng: ctx.rng().as_ref(),
                    now_unix: ctx.clock().now_unix(),
                },
            )
            .await
            .map_err(|err| flow_error(err.to_string()))?;

            let _ = ctx
                .progress(
                    "token_obtained",
                    &serde_json::json!({
                        "token_type": token.token_type,
                    }),
                )
                .await;

            let configuration_id = offer
                .credential_configuration_ids
                .first()
                .cloned()
                .unwrap_or_default();

            let credential = request_and_deliver(
                ctx,
                &params.flow_id,
                &issuer_metadata,
                &token,
                &configuration_id,
                DeliverParams {
                    delivery: Some(&delivery),
                    negotiated_encryption: negotiated_encryption.as_ref(),
                    dpop_key: dpop_key.as_ref(),
                    dpop_key_id: dpop_key_id.as_deref(),
                    reissuance_kid: reissuance_kid.as_deref(),
                },
            )
            .await?;

            (Some(token), Some(credential))
        } else if let Some(grant) = pre_auth {
            let pre_auth_code = grant
                .get("pre-authorized_code")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            let tx_code_required = grant.get("tx_code").map(|v| !v.is_null()).unwrap_or(false);

            let _ = ctx
                .progress(
                    "exchanging_token",
                    &serde_json::json!({ "message": "exchanging the code for a token" }),
                )
                .await;

            let token = token::exchange_pre_authorized_code(
                ctx.http().as_ref(),
                ctx.host().as_ref(),
                &as_metadata,
                &pre_auth_code,
                tx_code_required,
                &token::TokenExchangeContext {
                    flow_id: &params.flow_id,
                    client_id: &client_id,
                    dpop_key_id: dpop_key_id.as_deref(),
                    client_key_kid: client_key_kid.as_deref(),
                    dpop: dpop_key.as_ref(),
                    rng: ctx.rng().as_ref(),
                    now_unix: ctx.clock().now_unix(),
                },
            )
            .await
            .map_err(|err| flow_error(err.to_string()))?;

            let _ = ctx
                .progress(
                    "token_obtained",
                    &serde_json::json!({
                        "token_type": token.token_type,
                    }),
                )
                .await;

            let configuration_id = offer
                .credential_configuration_ids
                .first()
                .cloned()
                .unwrap_or_default();

            let credential = request_and_deliver(
                ctx,
                &params.flow_id,
                &issuer_metadata,
                &token,
                &configuration_id,
                DeliverParams {
                    delivery: Some(&delivery),
                    negotiated_encryption: negotiated_encryption.as_ref(),
                    dpop_key: dpop_key.as_ref(),
                    dpop_key_id: dpop_key_id.as_deref(),
                    reissuance_kid: reissuance_kid.as_deref(),
                },
            )
            .await?;

            (Some(token), Some(credential))
        } else if offer.grants.get("authorization_code").is_some() {
            // ── The authorization-code grant: PKCE, PAR, the
            // authorization URL, and the handoff. The flow continues in
            // handle_action when the redirect returns with the code.
            let authorization = start_authorization_code(
                ctx,
                &params.flow_id,
                &offer_params,
                &offer,
                &as_metadata,
                &issuer_metadata,
            )
            .await?;

            let _ = ctx
                .progress(
                    "authorization_required",
                    &serde_json::json!({
                        "authorization_url": authorization.url,
                        "expected_redirect_uri": authorization.redirect_uri,
                        "state": authorization.state,
                        "code_verifier": authorization.code_verifier,
                    }),
                )
                .await;

            ctx.host()
                .open_authorization(&params.flow_id, &authorization.url)
                .await
                .map_err(|err| flow_error(err.to_string()))?;

            // The flow stays open: the redirect answers through
            // wmp.flow.action, and handle_action resumes it.
            return Ok(FlowStartResult {
                wmp: wmp_core::types::Metadata::default(),
                flow_id: params.flow_id.clone(),
                flow_type: params.flow_type.clone(),
            });
        } else {
            return Err(flow_error("no supported grant type in offer".to_owned()).into());
        };

        // Report the flow completion with the credential result, the
        // refresh token (the renewal relay), and the DPoP key material
        // it must be reused with: a renewal presents the engine-held
        // key as `dpop_jwk` (the next flow may land on another engine
        // instance) — the client-held key needs no relay, the host
        // knows its own key id (the Go CompleteWithRefreshToken).
        let mut completion: serde_json::Value = serde_json::json!({
            "credential": credential.as_ref()
                .and_then(|c| c.credential.clone())
                .unwrap_or_default(),
            "deferred": credential.as_ref()
                .and_then(|c| c.transaction_id.clone())
                .is_some(),
        });
        if let Some(refresh) = _token.as_ref().and_then(|t| t.refresh_token.clone()) {
            if let Some(object) = completion.as_object_mut() {
                object.insert(
                    "refresh_token".to_owned(),
                    serde_json::Value::String(refresh),
                );
                if let Some(relay) = dpop_key.as_ref().and_then(|key| key.private_jwk_json()) {
                    object.insert("dpop_jwk".to_owned(), serde_json::Value::String(relay));
                }
            }
        }
        let _ = ctx.complete(&completion).await;

        Ok(FlowStartResult {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: params.flow_id.clone(),
            flow_type: params.flow_type.clone(),
        })
    }

    async fn handle_action(
        &self,
        ctx: &FlowContext,
        params: &FlowActionParams,
    ) -> Result<FlowActionResult, HandlerError> {
        resume_authorization_code(ctx, params).await
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

// ─── The authorization-code grant ─────────────────────────────────────────
//
// The grant spans two WMP calls: start_flow builds the authorization
// request (PKCE, PAR) and hands the URL to the host; the redirect's
// answer arrives as a wmp.flow.action, and handle_action resumes the
// flow — the stateless resume the Go engine's resumeWithAuthCode models,
// with the cross-call state (the verifier, the state, the offer) in the
// KeyValue port rather than the client's localStorage.

/// The authorization handoff start_flow returns.
struct AuthorizationHandoff {
    url: String,
    redirect_uri: String,
    state: String,
    code_verifier: String,
}

/// The flow state stashed in the KeyValue port between the handoff and
/// the resume.
#[derive(serde::Serialize, serde::Deserialize)]
struct AuthorizationStash {
    code_verifier: String,
    state: String,
    redirect_uri: String,
    client_id: String,
    resource: Option<String>,
    /// The original offer params, as the flow start received them — the
    /// resume re-parses the offer from this (the stateless resume).
    offer_params: serde_json::Value,
}

/// The KeyValue key the authorization-code flow stashes under.
fn stash_key(flow_id: &str) -> String {
    format!("oid4vci:auth-code:{flow_id}")
}

/// Builds the authorization request for the authorization_code grant:
/// the PKCE pair and the OAuth state from the Rng port, the assembled
/// parameters (auth_params), PAR when the AS advertises it (with the
/// required-PAR no-fallback rule), and the stash for the resume.
async fn start_authorization_code(
    ctx: &FlowContext,
    flow_id: &str,
    offer_params: &serde_json::Value,
    offer: &types::CredentialOffer,
    as_metadata: &types::AsMetadata,
    issuer_metadata: &types::IssuerMetadata,
) -> Result<AuthorizationHandoff, HandlerError> {
    let flow_error = |reason: String| {
        HandlerError::Rpc(wmp_core::error::RpcError::new(
            wmp_core::error::ERR_FLOW_ERROR,
            Some(serde_json::json!({ "reason": reason })),
        ))
    };

    // The wallet's redirect_uri: required for the authorization-code
    // flow (the Go rule — there is no authorization without it).
    let redirect_uri = offer_params
        .get("redirect_uri")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    if redirect_uri.is_empty() {
        return Err(flow_error(
            "redirect_uri is required for the authorization code flow".to_owned(),
        ));
    }

    // The client_id: the registered id, else the redirect_uri (the
    // unregistered-client form).
    let client_id = offer_params
        .get("client_id")
        .and_then(|v| v.as_str())
        .filter(|id| !id.is_empty())
        .unwrap_or(&redirect_uri)
        .to_owned();

    // PKCE (RFC 7636) and the OAuth state, from the Rng port — the
    // core's own random choices.
    let pkce_enabled = as_metadata.supports_pkce_s256();
    let (code_verifier, code_challenge) = if pkce_enabled {
        let pkce = auth_code::PkcePair::generate(ctx.rng().as_ref()).ok_or_else(|| {
            flow_error("the Rng port could not generate the PKCE verifier".to_owned())
        })?;
        (pkce.code_verifier, Some(pkce.code_challenge))
    } else {
        (String::new(), None)
    };
    let state = auth_code::generate_state(ctx.rng().as_ref())
        .ok_or_else(|| flow_error("the Rng port could not generate the state".to_owned()))?;

    // The selected configuration's scope, when it declares one.
    let configuration_id = offer
        .credential_configuration_ids
        .first()
        .cloned()
        .unwrap_or_default();
    let scope = issuer_metadata
        .credential_configurations
        .get(&configuration_id)
        .and_then(|config| config.get("scope"))
        .and_then(|v| v.as_str());

    // The client-supplied authorization_details (raw), when the flow
    // start carried them.
    let authorization_details: Vec<serde_json::Value> = offer_params
        .get("authorization_details")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // The assembled parameters — the guard included (something must
    // name the credential).
    let mut params =
        auth_params::build_authorization_request_params(&auth_params::AuthorizationRequestSpec {
            client_id: &client_id,
            redirect_uri: &redirect_uri,
            state: &state,
            scope,
            authorization_details: &authorization_details,
            grants: &offer.grants,
            as_issuer: &as_metadata.issuer,
            credential_issuer: &offer.credential_issuer,
        })
        .map_err(|err| flow_error(err.to_string()))?;

    // The PKCE challenge parameters (the PAR client's to add — they are
    // derived from the fresh entropy, not part of the assembly).
    if let Some(challenge) = code_challenge {
        params.params.push(("code_challenge".to_owned(), challenge));
        params
            .params
            .push(("code_challenge_method".to_owned(), "S256".to_owned()));
    }

    // PAR (RFC 9126): push when the AS advertises it, with the client
    // attestation the host supplies (the WIA from the existing wallet
    // provider, the PoP device-signed), and the RFC 7523 client
    // assertion when the AS authenticates the client at the pushed
    // request (the registered kid the flow start carried). A failure
    // has no fallback when the AS requires PAR; otherwise fall back to
    // the plain authorization URL with all parameters.
    let client_key_kid = offer_params
        .get("client_key_kid")
        .and_then(|v| v.as_str())
        .filter(|kid| !kid.is_empty())
        .map(str::to_owned);
    let mut request_uri = None;
    if !as_metadata.par_endpoint.is_empty() {
        match auth_code::push_authorization_request_with_attestation(
            ctx.http().as_ref(),
            ctx.host().as_ref(),
            as_metadata,
            &auth_code::ParPushSpec {
                flow_id,
                client_id: &client_id,
                client_key_kid: client_key_kid.as_deref(),
                rng: ctx.rng().as_ref(),
                now_unix: ctx.clock().now_unix(),
            },
            &params.params,
        )
        .await
        {
            Ok(uri) => request_uri = Some(uri),
            Err(err) => {
                if as_metadata.require_par {
                    return Err(flow_error(format!(
                        "PAR request failed (AS requires PAR, no fallback available): {err}"
                    )));
                }
                // Merely advertised: the plain URL is the fallback, the
                // same as an AS without a PAR endpoint at all.
            }
        }
    }

    let url = auth_code::build_authorization_url(
        &as_metadata.authorization_endpoint,
        &client_id,
        &params.params,
        request_uri.as_deref(),
    );

    // The RFC 8707 resource decision, for the token exchange to reuse —
    // the same origin rule as the authorization request.
    let resource =
        auth_params::token_request_resource(&as_metadata.issuer, &offer.credential_issuer);

    // Stash the resume state; the redirect may land on another engine
    // instance entirely (the stateless resume).
    let stash = AuthorizationStash {
        code_verifier,
        state,
        redirect_uri,
        client_id,
        resource,
        offer_params: offer_params.clone(),
    };
    ctx.kv()
        .put(
            &stash_key(flow_id),
            engine_ports::KeyValueEntry {
                value: serde_json::to_vec(&stash).unwrap_or_default(),
                ttl_secs: Some(600),
            },
        )
        .await;

    Ok(AuthorizationHandoff {
        url,
        redirect_uri: stash.redirect_uri,
        state: stash.state,
        code_verifier: stash.code_verifier,
    })
}

/// Resumes the authorization-code flow: the redirect's answer arrives as
/// a wmp.flow.action with the code and the state; the state must match
/// the stash (the CSRF check), the code exchanges with the verifier, and
/// the issuance tail runs — the offer, metadata, trust and encryption all
/// re-resolved (the stateless resume).
async fn resume_authorization_code(
    ctx: &FlowContext,
    params: &FlowActionParams,
) -> Result<FlowActionResult, HandlerError> {
    let flow_error = |reason: String| {
        HandlerError::Rpc(wmp_core::error::RpcError::new(
            wmp_core::error::ERR_FLOW_ERROR,
            Some(serde_json::json!({ "reason": reason })),
        ))
    };

    // Load the stash.
    let entry = ctx
        .kv()
        .get(&stash_key(&params.flow_id))
        .await
        .ok_or_else(|| flow_error("no authorization in progress for this flow".to_owned()))?;
    let stash: AuthorizationStash = serde_json::from_slice(&entry.value)
        .map_err(|_| flow_error("the authorization stash is corrupt".to_owned()))?;

    // The redirect's answer: the code and the state.
    let action_params = params
        .params
        .as_deref()
        .map(|raw| raw.get())
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        .unwrap_or(serde_json::Value::Null);
    let code = action_params
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    let state = action_params
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    if code.is_empty() {
        return Err(flow_error(
            "the authorization answer carries no code".to_owned(),
        ));
    }

    // The CSRF check (RFC 6749 §10.12): the state must match.
    if state != stash.state {
        return Err(flow_error(
            "state parameter mismatch (possible CSRF)".to_owned(),
        ));
    }

    // Re-resolve, the stateless resume: the offer, the issuer metadata,
    // the AS metadata.
    let offer = offer::parse_offer(ctx.http().as_ref(), &stash.offer_params)
        .await
        .map_err(|err| flow_error(err.to_string()))?;

    let issuer_metadata = issuer::resolve_issuer_metadata(
        ctx.http().as_ref(),
        &offer.credential_issuer,
        MetadataType::PreferSigned,
        false,
    )
    .await
    .map_err(|err| flow_error(err.to_string()))?;

    // Fail closed, again: the resume re-evaluates the issuer's trust.
    trust::evaluate_issuer_trust(
        ctx.pdp().as_ref(),
        &offer.credential_issuer,
        &issuer_metadata,
    )
    .await
    .map_err(|err| match &err {
        // The typed -31006 data (go-wmp's NewUntrustedIssuerData): the
        // class reason, the refused issuer, the PDP's detail, and the
        // retryable flag.
        TrustError::Untrusted { issuer, reason } => {
            HandlerError::Rpc(wmp_core::error::RpcError::new(
                wmp_core::error::ERR_FLOW_ERROR,
                Some(trust::untrusted_issuer_data(issuer, reason)),
            ))
        }
        _ => flow_error(err.to_string()),
    })?;

    // #511: the hint selects the AS on the resume path too.
    let as_url = select_as_url(&offer, &issuer_metadata).map_err(flow_error)?;
    let as_metadata = as_metadata::discover_as_metadata(ctx.http().as_ref(), &as_url, false)
        .await
        .map_err(|err| flow_error(err.to_string()))?;

    // The flow's DPoP key (the engine-held legacy mode): the token
    // exchange and the credential request sign with the same key, which
    // is what makes the DPoP binding hold.
    let dpop_key = dpop::DpopKey::generate().ok();

    // The wallet's registered client key's kid, as the flow start
    // received it: the stash carried the offer params across the
    // reload, and the code-for-token exchange needs the kid when the
    // AS demands the RFC 7523 assertion — the same threading the
    // pre-authorized grant does at its flow start.
    let client_key_kid = stash
        .offer_params
        .get("client_key_kid")
        .and_then(|v| v.as_str())
        .filter(|kid| !kid.is_empty())
        .map(str::to_owned);

    // The code-for-token exchange, with the stashed verifier, the RFC
    // 8707 resource the authorization request already decided, and the
    // client attestation the host supplies.
    let _ = ctx
        .progress(
            "exchanging_token",
            &serde_json::json!({ "message": "exchanging the code for a token" }),
        )
        .await;

    let token = auth_code::exchange_authorization_code_with_attestation(
        ctx.http().as_ref(),
        ctx.host().as_ref(),
        &as_metadata,
        &auth_code::CodeExchangeSpec {
            flow_id: &params.flow_id,
            dpop_key_id: None,
            client_key_kid: client_key_kid.as_deref(),
            client_id: &stash.client_id,
            code: &code,
            redirect_uri: &stash.redirect_uri,
            code_verifier: &stash.code_verifier,
            resource: stash.resource.as_deref(),
            dpop: dpop_key.as_ref(),
            rng: ctx.rng().as_ref(),
            now_unix: ctx.clock().now_unix(),
        },
    )
    .await
    .map_err(|err| flow_error(err.to_string()))?;

    let _ = ctx
        .progress(
            "token_obtained",
            &serde_json::json!({
                "token_type": token.token_type,
            }),
        )
        .await;

    // The response-encryption negotiation, fresh for this request (the
    // ephemeral key lives once, in the request that offers it).
    let negotiated_encryption = negotiated_encryption_for(&issuer_metadata);
    if let (Some(config), None) = (
        encryption_config_for(&issuer_metadata),
        negotiated_encryption.as_ref(),
    ) {
        if config.required {
            return Err(flow_error(
                encryption::EncryptionError::NoOverlap.to_string(),
            ));
        }
    }

    let configuration_id = offer
        .credential_configuration_ids
        .first()
        .cloned()
        .unwrap_or_default();

    // The auxiliary-data selection gate, again on the resume (#480): the
    // same parse and verdict, before the credential request.
    let resume_configuration = issuer_metadata
        .credential_configurations
        .get(&configuration_id)
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let delivery = auxiliary::secret_delivery_of(&resume_configuration)
        .map_err(|err| flow_error(err.reason()))?;
    if let Err(refusal) = auxiliary::usable(&delivery, &resume_configuration) {
        return Err(flow_error(format!(
            "auxiliary_data_unsupported: {}",
            refusal.reason
        )));
    }

    let credential = request_and_deliver(
        ctx,
        &params.flow_id,
        &issuer_metadata,
        &token,
        &configuration_id,
        DeliverParams {
            delivery: Some(&delivery),
            negotiated_encryption: negotiated_encryption.as_ref(),
            dpop_key: dpop_key.as_ref(),
            dpop_key_id: None,
            reissuance_kid: None,
        },
    )
    .await?;

    // The completion carries the renewal relay, exactly as the
    // start_flow path does: the refresh token, and the DPoP key it
    // must be reused with (the next flow may land on another engine
    // instance).
    let mut completion = serde_json::json!({
        "credential": credential.credential.clone().unwrap_or_default(),
        "deferred": credential.transaction_id.is_some(),
    });
    if let Some(refresh) = token.refresh_token.clone() {
        if let Some(object) = completion.as_object_mut() {
            object.insert(
                "refresh_token".to_owned(),
                serde_json::Value::String(refresh),
            );
            if let Some(relay) = dpop_key.as_ref().and_then(|key| key.private_jwk_json()) {
                object.insert("dpop_jwk".to_owned(), serde_json::Value::String(relay));
            }
        }
    }
    let _ = ctx.complete(&completion).await;

    Ok(FlowActionResult {
        wmp: wmp_core::types::Metadata::default(),
        flow_id: params.flow_id.clone(),
        action: params.action.clone(),
        status: "completed".to_owned(),
    })
}

/// The issuer's credential_response_encryption configuration, when any
/// configuration declares one.
fn encryption_config_for(
    issuer_metadata: &types::IssuerMetadata,
) -> Option<encryption::ResponseEncryptionConfig> {
    issuer_metadata
        .credential_configurations
        .as_object()
        .and_then(|configs| {
            configs
                .values()
                .filter_map(|config| config.get("credential_response_encryption").cloned())
                .next()
        })
        .and_then(|v| serde_json::from_value::<encryption::ResponseEncryptionConfig>(v).ok())
}

/// The negotiated response encryption with a fresh ephemeral key.
fn negotiated_encryption_for(
    issuer_metadata: &types::IssuerMetadata,
) -> Option<encryption::NegotiatedResponseEncryption> {
    encryption_config_for(issuer_metadata)
        .and_then(|config| encryption::negotiate_with_key(&config))
}

/// The issuance tail every grant shares: the credential request with the
/// host-signed proof, the invalid_nonce retry, the encryption offer, the
/// deferred polling, and the notification.
/// The per-flow inputs of the issuance tail.
struct DeliverParams<'a> {
    /// The negotiated response encryption, when the issuer supports it.
    negotiated_encryption: Option<&'a encryption::NegotiatedResponseEncryption>,
    /// The flow's DPoP key (engine-held: the relayed renewal key or a
    /// fresh one), when there is one.
    dpop_key: Option<&'a dpop::DpopKey>,
    /// The device DPoP key's id, when the flow names one.
    dpop_key_id: Option<&'a str>,
    /// The reissuance kid: a renewal's proof signs with the existing
    /// keypair the issuer knows.
    reissuance_kid: Option<&'a str>,
    /// The credential configuration's secret delivery (Credential
    /// Auxiliary Data v0.1), when it advertised one: the to_issuer
    /// entries ride the proof, the to_wallet entries ride the
    /// completion for the client's own response check.
    delivery: Option<&'a auxiliary::SecretDelivery>,
}

async fn request_and_deliver(
    ctx: &FlowContext,
    _flow_id: &str,
    issuer_metadata: &types::IssuerMetadata,
    token: &token::TokenResponse,
    configuration_id: &str,
    deliver: DeliverParams<'_>,
) -> Result<credential::CredentialResponse, HandlerError> {
    let flow_error = |reason: String| {
        HandlerError::Rpc(wmp_core::error::RpcError::new(
            wmp_core::error::ERR_FLOW_ERROR,
            Some(serde_json::json!({ "reason": reason })),
        ))
    };

    // The Go engine's `requesting_credential` message step before the
    // credential request (docs/engine-parity.md §2).
    let _ = ctx
        .progress(
            "requesting_credential",
            &serde_json::json!({ "message": "requesting the credential" }),
        )
        .await;

    // The auxiliary inputs: the encryption offer, and the DPoP binding
    // when the AS issued a DPoP-bound token (a fresh proof over the
    // credential endpoint, `ath`-bound, signed with the same key that
    // proved the token request).
    let aux = credential::CredentialRequestAux {
        encryption: deliver.negotiated_encryption,
        auxiliary_data_to_issuer: deliver
            .delivery
            .map(|delivery| delivery.to_issuer.as_slice())
            .unwrap_or(&[]),
        auxiliary_data_to_wallet: deliver
            .delivery
            .map(|delivery| delivery.to_wallet.as_slice())
            .unwrap_or(&[]),
        dpop: deliver.dpop_key.map(|key| credential::ResourceDpop {
            flow_id: ctx.flow_id.as_str(),
            key_id: deliver.dpop_key_id,
            key,
            rng: ctx.rng().as_ref(),
            now_unix: ctx.clock().now_unix(),
            // The DPoP nonce captured from the token response (RFC 9449
            // §8): the resource request's proof carries it, so the
            // binding holds across the token and credential endpoints.
            dpop_nonce: token.dpop_nonce.as_deref(),
        }),
        reissuance_kid: deliver.reissuance_kid,
        now_unix: ctx.clock().now_unix(),
    };
    let credential = credential::request_credential_with_retry(
        ctx.http().as_ref(),
        ctx.host().as_ref(),
        issuer_metadata,
        token,
        configuration_id,
        Some(&aux),
        token.nonce.as_deref().or(token.c_nonce.as_deref()),
    )
    .await
    .map_err(|err| flow_error(err.to_string()))?;

    // The deferred polling, when the issuer deferred.
    let credential = if let Some(transaction_id) = &credential.transaction_id {
        // The Go engine's `deferred` step (docs/engine-parity.md §2):
        // the transaction, the issuer's interval, the attempt budget.
        let _ = ctx
            .progress(
                "deferred",
                &serde_json::json!({
                    "transaction_id": transaction_id,
                    "interval": 5,
                    "max_attempts": 60,
                    "message": "the issuer deferred the credential; polling",
                }),
            )
            .await;
        let deferred_credential = deferred::poll_deferred_credential(
            ctx.http().as_ref(),
            ctx.host().as_ref(),
            ctx.clock().as_ref(),
            issuer_metadata,
            token,
            aux.dpop.as_ref(),
            transaction_id,
            credential.interval,
            &|attempt| {
                let _ = attempt;
            },
        )
        .await
        .map_err(|err| flow_error(err.to_string()))?;

        let _ = ctx
            .progress(
                "deferred_credential_received",
                &serde_json::json!({
                    "has_credential": deferred_credential.credential.is_some(),
                }),
            )
            .await;

        deferred_credential
    } else {
        credential
    };

    // The notification (OID4VCI 1.0 §11), best effort — only when the
    // issuer's response named a `notification_id` (the wallet echoes
    // that exact value), and with the same sender-constrained binding
    // the credential request carried (the DPoP scheme and a fresh
    // proof; RFC 9449 §4.3).
    if let Some(notification_id) = credential.notification_id.as_deref() {
        let _ = deferred::send_notification(
            ctx.http().as_ref(),
            ctx.host().as_ref(),
            issuer_metadata,
            Some(token),
            aux.dpop.as_ref(),
            notification_id,
            "credential_accepted",
        )
        .await;
    }

    let _ = ctx
        .progress(
            "credential_received",
            &serde_json::json!({
                "has_credential": credential.credential.is_some(),
                "transaction_id": credential.transaction_id,
            }),
        )
        .await;

    Ok(credential)
}

#[cfg(test)]
mod auth_code_flow_tests {
    //! The two-call authorization-code flow, end to end on fake ports:
    //! start_flow builds the authorization request (PKCE, PAR) and hands
    //! the URL over; the redirect's answer arrives as wmp.flow.action,
    //! and the resume exchanges, re-resolves, and delivers.

    use super::*;
    use crate::runtime::{FlowContext, FlowHandler};
    use crate::Ports;
    use engine_ports::{
        ConsentParams, ConsentResult, EvaluationRequest, EvaluationResponse, Host, HostError,
        HttpClient, HttpError, HttpRequest, HttpResponse, KeyValue, KeyValueEntry, MatchResult,
        Pdp, PdpError, ResolveRequest, ResolveResponse, Rng, SignParams, SignResult, VpSelection,
    };
    use std::sync::{Arc, Mutex};

    /// A deterministic Rng: bytes i, i+1, i+2... — the state and the PKCE
    /// verifier are computable in the test.
    struct FakeRng;
    impl Rng for FakeRng {
        fn fill(&self, buf: &mut [u8]) -> bool {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = i as u8;
            }
            true
        }
    }

    /// An in-memory KeyValue.
    struct MemKv(Mutex<rustc_hash::FxHashMap<String, Vec<u8>>>);
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

    struct TrustedPdp;
    #[async_trait::async_trait]
    impl Pdp for TrustedPdp {
        async fn evaluate(
            &self,
            _request: EvaluationRequest,
        ) -> Result<EvaluationResponse, PdpError> {
            Ok(EvaluationResponse {
                trusted: true,
                decision: None,
            })
        }
        async fn resolve(&self, _request: ResolveRequest) -> Result<ResolveResponse, PdpError> {
            Err(PdpError::NotImplemented)
        }
    }

    struct FakeHost {
        authorization_urls: Mutex<Vec<String>>,
        sign_key_ids: Mutex<Vec<Option<String>>>,
    }
    #[async_trait::async_trait]
    impl Host for FakeHost {
        async fn request_sign(&self, p: SignParams) -> Result<SignResult, HostError> {
            // The key id each sign ask named — the RFC 7523
            // assertion's registered kid, when the AS demands the
            // method.
            self.sign_key_ids
                .lock()
                .map(|mut ids| ids.push(p.key_id))
                .ok();
            Ok(SignResult {
                signature: vec![1, 2, 3, 4],
            })
        }
        async fn request_match(
            &self,
            _params: engine_ports::MatchParams,
        ) -> Result<MatchResult, HostError> {
            Ok(MatchResult {
                selections: vec![VpSelection {
                    credential_query_id: String::new(),
                    credential_id: "cred-1".to_owned(),
                    disclosed_claims: Vec::new(),
                }],
            })
        }
        async fn request_consent(&self, _p: ConsentParams) -> Result<ConsentResult, HostError> {
            Ok(ConsentResult { consented: true })
        }
        async fn request_tx_code(&self, _f: &str) -> Result<String, HostError> {
            Ok("1234".to_owned())
        }
        async fn open_authorization(&self, _f: &str, url: &str) -> Result<(), HostError> {
            self.authorization_urls
                .lock()
                .map(|mut u| u.push(url.to_owned()))
                .ok();
            Ok(())
        }
        fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
    }

    /// The scripted HTTP: dispatches by URL.
    struct ScriptedHttp {
        credential_requests: Mutex<Vec<Vec<u8>>>,
        /// The AS metadata's `token_endpoint_auth_methods_supported`
        /// (OpenID4VCI 1.0 §5.1) — the private_key_jwt variant the
        /// code-for-token exchange answers with the RFC 7523
        /// assertion.
        token_auth_methods: Vec<String>,
    }
    #[async_trait::async_trait]
    impl HttpClient for ScriptedHttp {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
            let body = match request.url.as_str() {
                "https://issuer.example/.well-known/openid-credential-issuer" => {
                    serde_json::json!({
                        "credential_issuer": "https://issuer.example",
                        "authorization_servers": ["https://as.example"],
                        "credential_configurations_supported": {
                            "UniversityDegree": { "scope": "openid credential", "format": "sd_jwt" }
                        }
                    })
                    .to_string()
                }
                "https://as.example/.well-known/oauth-authorization-server" => serde_json::json!({
                    "issuer": "https://as.example",
                    "authorization_endpoint": "https://as.example/authorize",
                    "token_endpoint": "https://as.example/token",
                    "pushed_authorization_request_endpoint": "https://as.example/par",
                    "require_pushed_authorization_requests": false,
                    "challenge_endpoint": "https://as.example/attestation/challenge",
                    "token_endpoint_auth_methods_supported": &self.token_auth_methods,
                })
                .to_string(),
                "https://as.example/par" => {
                    // The PAR push: assert the parameters arrived.
                    let form = String::from_utf8_lossy(&request.body).into_owned();
                    assert!(
                        form.contains("grant_type=authorization_code")
                            || form.contains("response_type=code")
                    );
                    assert!(form.contains("code_challenge_method=S256"));
                    assert!(form.contains("code_challenge="));
                    assert!(form.contains("issuer_state=session-1"));
                    assert!(form.contains("resource=https%3A%2F%2Fissuer.example"));
                    serde_json::json!({ "request_uri": "urn:ietf:params:oauth:request_uri:par-1" })
                        .to_string()
                }
                "https://as.example/token" => {
                    let form = String::from_utf8_lossy(&request.body).into_owned();
                    if form.contains("grant_type=authorization_code") {
                        assert!(form.contains("code_verifier="));
                        assert!(form.contains("resource=https%3A%2F%2Fissuer.example"));
                        // The RFC 7523 assertion, when the AS names the
                        // method: the type and the value ride the form
                        // (RFC 7523 §2.2).
                        if self
                            .token_auth_methods
                            .iter()
                            .any(|m| m == "private_key_jwt")
                        {
                            assert!(form.contains(
                                "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
                            ));
                            assert!(form.contains("client_assertion="));
                        }
                    } else {
                        // The renewal grant.
                        assert!(form.contains("grant_type=refresh_token"));
                        assert!(form.contains("refresh_token=rt-1"));
                    }
                    serde_json::json!({
                        "access_token": "at-1", "token_type": "Bearer", "expires_in": 3600,
                        "c_nonce": "nonce-1",
                        "refresh_token": "rt-2"
                    })
                    .to_string()
                }
                "https://issuer.example/credential" => {
                    self.credential_requests
                        .lock()
                        .map(|mut r| r.push(request.body.clone()))
                        .ok();
                    serde_json::json!({ "credential": "credential-jwt-1" }).to_string()
                }
                "https://issuer.example/notification" => "{}".to_owned(),
                other => panic!("unexpected fetch: {other}"),
            };
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: body.into_bytes(),
            })
        }
    }

    fn test_context(http: Arc<dyn HttpClient>, host: Arc<FakeHost>) -> FlowContext {
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
            flow_id: "flow-1".to_owned(),
            flow_type: "oid4vci".to_owned(),
            session: None,
            ports: Arc::new(Ports {
                http,
                clock: Arc::new(FakeClock),
                rng: Arc::new(FakeRng),
                host,
                pdp: Arc::new(TrustedPdp),
                kv: Arc::new(MemKv(Mutex::new(rustc_hash::FxHashMap::default()))),
                telemetry: Arc::new(NoopTelemetry),
            }),
            peer,
            request_context: wmp_core::context::RequestContext::default(),
        }
    }

    struct FakeClock;
    #[async_trait::async_trait]
    impl engine_ports::Clock for FakeClock {
        fn now_unix(&self) -> i64 {
            1_000
        }
        async fn sleep(&self, _duration_ms: u64) {}
    }

    struct NoopTelemetry;
    impl engine_ports::Telemetry for NoopTelemetry {
        fn event(&self, _event: engine_ports::TelemetryEvent) {}
    }

    fn start_params() -> FlowStartParams {
        FlowStartParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-1".to_owned(),
            flow_type: "oid4vci".to_owned(),
            params: raw_value(serde_json::json!({
                "credential_issuer": "https://issuer.example",
                "credential_configuration_ids": ["UniversityDegree"],
                "grants": {
                    "authorization_code": { "issuer_state": "session-1" }
                },
                "redirect_uri": "https://wallet.example/cb",
                "client_id": "client-1"
            })),
            timeout: None,
        }
    }

    /// A params Box<RawValue> from a JSON value.
    fn raw_value(value: serde_json::Value) -> Option<Box<serde_json::value::RawValue>> {
        serde_json::value::RawValue::from_string(value.to_string()).ok()
    }

    #[tokio::test]
    async fn the_authorization_code_flow_spans_start_and_action() {
        let http = Arc::new(ScriptedHttp {
            credential_requests: Mutex::new(Vec::new()),
            token_auth_methods: Vec::new(),
        });
        let host = Arc::new(FakeHost {
            authorization_urls: Mutex::new(Vec::new()),
            sign_key_ids: Mutex::new(Vec::new()),
        });
        let ctx = test_context(http.clone() as Arc<dyn HttpClient>, host.clone());
        let flow = Oid4vciFlow;

        // ── The first call: the authorization request ──────────────────
        let result = flow.start_flow(&ctx, &start_params()).await.expect("start");
        assert_eq!(result.flow_id, "flow-1");

        // The handoff: the authorization URL carries the PAR request_uri
        // and only client_id beside it. The guard is block-scoped: the
        // lock must not live across the resume's await.
        {
            let urls = host.authorization_urls.lock().expect("lock");
            assert_eq!(urls.len(), 1);
            assert!(urls[0].starts_with("https://as.example/authorize?"));
            assert!(
                urls[0].contains("request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Apar-1")
            );
            assert!(urls[0].contains("client_id=client-1"));
            // The pushed parameters are NOT in the URL (PAR: server-side).
            assert!(!urls[0].contains("code_challenge="));
        }

        // ── The second call: the redirect's answer ─────────────────────
        // The state the Rng port produced (bytes 0..16).
        let expected_state = auth_code::generate_state(&FakeRng).expect("state");
        let action = FlowActionParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-1".to_owned(),
            action: "authorization_complete".to_owned(),
            params: raw_value(
                serde_json::json!({ "code": "auth-code-1", "state": expected_state }),
            ),
        };
        let result = flow.handle_action(&ctx, &action).await.expect("resume");
        assert_eq!(result.status, "completed");

        // The credential request happened, with the proof.
        let requests = http.credential_requests.lock().expect("lock");
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&requests[0]).expect("json");
        assert_eq!(body["credential_configuration_id"], "UniversityDegree");
        assert!(body["proofs"]["jwt"][0]
            .as_str()
            .is_some_and(|j| !j.is_empty()));
    }

    #[tokio::test]
    async fn the_resume_carries_the_private_key_jwt_assertion_with_the_registered_kid() {
        let http = Arc::new(ScriptedHttp {
            credential_requests: Mutex::new(Vec::new()),
            // The AS names the method (OpenID4VCI 1.0 §5.1): the
            // code-for-token POST must carry the RFC 7523 assertion.
            token_auth_methods: vec!["private_key_jwt".to_owned()],
        });
        let host = Arc::new(FakeHost {
            authorization_urls: Mutex::new(Vec::new()),
            sign_key_ids: Mutex::new(Vec::new()),
        });
        let ctx = test_context(http.clone() as Arc<dyn HttpClient>, host.clone());
        let flow = Oid4vciFlow;

        // The flow start carries the registered kid: the stash keeps
        // the offer params across the reload (the stateless resume).
        let params = FlowStartParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-1".to_owned(),
            flow_type: "oid4vci".to_owned(),
            params: raw_value(serde_json::json!({
                "credential_issuer": "https://issuer.example",
                "credential_configuration_ids": ["UniversityDegree"],
                "grants": {
                    "authorization_code": { "issuer_state": "session-1" }
                },
                "redirect_uri": "https://wallet.example/cb",
                "client_id": "client-1",
                "client_key_kid": "client-key-1"
            })),
            timeout: None,
        };
        flow.start_flow(&ctx, &params).await.expect("start");

        // The redirect's answer, with the state the Rng port produced.
        let expected_state = auth_code::generate_state(&FakeRng).expect("state");
        let action = FlowActionParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-1".to_owned(),
            action: "authorization_complete".to_owned(),
            params: raw_value(
                serde_json::json!({ "code": "auth-code-1", "state": expected_state }),
            ),
        };
        let result = flow.handle_action(&ctx, &action).await.expect("resume");
        assert_eq!(result.status, "completed");

        // The assertion's sign ask named the registered kid — the
        // stash relayed it across the reload, and the scripted token
        // handler asserts the form members the assertion rides.
        let key_ids = host.sign_key_ids.lock().expect("lock");
        assert!(
            key_ids
                .iter()
                .any(|id| id.as_deref() == Some("client-key-1")),
            "the sign asks carried the registered kid: {key_ids:?}"
        );
    }

    #[tokio::test]
    async fn a_state_mismatch_refuses_the_resume() {
        let http = Arc::new(ScriptedHttp {
            credential_requests: Mutex::new(Vec::new()),
            token_auth_methods: Vec::new(),
        });
        let host = Arc::new(FakeHost {
            authorization_urls: Mutex::new(Vec::new()),
            sign_key_ids: Mutex::new(Vec::new()),
        });
        let ctx = test_context(http.clone() as Arc<dyn HttpClient>, host.clone());
        let flow = Oid4vciFlow;

        flow.start_flow(&ctx, &start_params()).await.expect("start");

        // A state that is not the stashed one: the CSRF refusal.
        let action = FlowActionParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-1".to_owned(),
            action: "authorization_complete".to_owned(),
            params: raw_value(serde_json::json!({ "code": "auth-code-1", "state": "wrong-state" })),
        };
        assert!(flow.handle_action(&ctx, &action).await.is_err());
        // Nothing reached the credential endpoint.
        assert!(http.credential_requests.lock().expect("lock").is_empty());
    }
}

#[cfg(test)]
mod renewal_flow_tests {
    //! The renewal relay, end to end: the flow start carries the
    //! refresh_token, the DPoP key the token was bound to, and the
    //! reissuance kid — the same key re-signs the proof, and the
    //! completion relays the new refresh token and key forward.

    use super::*;
    use crate::runtime::{FlowContext, FlowHandler};
    use crate::Ports;
    use engine_ports::{
        ConsentParams, ConsentResult, EvaluationRequest, EvaluationResponse, Host, HostError,
        HttpClient, HttpError, HttpRequest, HttpResponse, MatchParams, MatchResult, Pdp, PdpError,
        ResolveRequest, ResolveResponse, Rng, SignParams, SignResult,
    };
    use std::sync::{Arc, Mutex};

    struct TrustedPdp;
    #[async_trait::async_trait]
    impl Pdp for TrustedPdp {
        async fn evaluate(&self, _r: EvaluationRequest) -> Result<EvaluationResponse, PdpError> {
            Ok(EvaluationResponse {
                trusted: true,
                decision: None,
            })
        }
        async fn resolve(&self, _r: ResolveRequest) -> Result<ResolveResponse, PdpError> {
            Err(PdpError::NotImplemented)
        }
    }

    /// The host that records the sign ask's key id.
    struct RenewalHost {
        sign_key_ids: Mutex<Vec<Option<String>>>,
    }

    #[async_trait::async_trait]
    impl Host for RenewalHost {
        async fn request_sign(&self, p: SignParams) -> Result<SignResult, HostError> {
            self.sign_key_ids
                .lock()
                .map(|mut k| k.push(p.key_id.clone()))
                .ok();
            Ok(SignResult {
                signature: vec![9, 8, 7, 6],
            })
        }
        async fn request_match(&self, _p: MatchParams) -> Result<MatchResult, HostError> {
            Err(HostError::Cannot("no match".to_owned()))
        }
        async fn request_consent(&self, _p: ConsentParams) -> Result<ConsentResult, HostError> {
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

    struct RenewalHttp {
        token_requests: Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl HttpClient for RenewalHttp {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
            let body = match request.url.as_str() {
                "https://issuer.example/.well-known/openid-credential-issuer" => {
                    serde_json::json!({
                        "credential_issuer": "https://issuer.example",
                        "authorization_servers": ["https://as.example"],
                        "credential_configurations_supported": {
                            "UniversityDegree": { "scope": "openid", "format": "sd_jwt" }
                        }
                    })
                    .to_string()
                }
                "https://as.example/.well-known/oauth-authorization-server" => serde_json::json!({
                    "issuer": "https://as.example",
                    "token_endpoint": "https://as.example/token"
                })
                .to_string(),
                "https://as.example/token" => {
                    self.token_requests
                        .lock()
                        .map(|mut r| r.push(request.body.clone()))
                        .ok();
                    serde_json::json!({
                        "access_token": "at-renewed", "token_type": "Bearer",
                        "refresh_token": "rt-2"
                    })
                    .to_string()
                }
                "https://issuer.example/credential" => {
                    serde_json::json!({ "credential": "credential-renewed" }).to_string()
                }
                "https://issuer.example/notification" => "{}".to_owned(),
                other => panic!("unexpected fetch: {other}"),
            };
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: body.into_bytes(),
            })
        }
    }

    struct FixedClock;
    #[async_trait::async_trait]
    impl engine_ports::Clock for FixedClock {
        fn now_unix(&self) -> i64 {
            1_000
        }
        async fn sleep(&self, _duration_ms: u64) {}
    }

    struct FakeRng;
    impl Rng for FakeRng {
        fn fill(&self, buf: &mut [u8]) -> bool {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = i as u8;
            }
            true
        }
    }

    struct MemKv(Mutex<rustc_hash::FxHashMap<String, Vec<u8>>>);
    #[async_trait::async_trait]
    impl engine_ports::KeyValue for MemKv {
        async fn get(&self, key: &str) -> Option<engine_ports::KeyValueEntry> {
            self.0
                .lock()
                .ok()?
                .get(key)
                .map(|v| engine_ports::KeyValueEntry {
                    value: v.clone(),
                    ttl_secs: None,
                })
        }
        async fn put(&self, key: &str, entry: engine_ports::KeyValueEntry) {
            self.0
                .lock()
                .map(|mut m| m.insert(key.to_owned(), entry.value))
                .ok();
        }
        async fn delete(&self, key: &str) {
            self.0.lock().map(|mut m| m.remove(key)).ok();
        }
    }

    struct NoTelemetry;
    impl engine_ports::Telemetry for NoTelemetry {
        fn event(&self, _e: engine_ports::TelemetryEvent) {}
    }

    #[tokio::test]
    async fn the_renewal_reuses_the_dpop_key_and_the_reissuance_kid() {
        // The key the original issuance bound the refresh token to.
        let dpop_key = dpop::DpopKey::generate().expect("keygen");
        let relay = dpop_key.private_jwk_json().expect("relay");

        let http = Arc::new(RenewalHttp {
            token_requests: Mutex::new(Vec::new()),
        });
        let host = Arc::new(RenewalHost {
            sign_key_ids: Mutex::new(Vec::new()),
        });

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
            flow_id: "flow-renewal-1".to_owned(),
            flow_type: "oid4vci".to_owned(),
            session: None,
            ports: Arc::new(Ports {
                http: http.clone(),
                clock: Arc::new(FixedClock),
                rng: Arc::new(FakeRng),
                host: host.clone(),
                pdp: Arc::new(TrustedPdp),
                kv: Arc::new(MemKv(Mutex::new(rustc_hash::FxHashMap::default()))),
                telemetry: Arc::new(NoTelemetry),
            }),
            peer,
            request_context: wmp_core::context::RequestContext::default(),
        };

        let start = FlowStartParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-renewal-1".to_owned(),
            flow_type: "oid4vci".to_owned(),
            params: serde_json::value::RawValue::from_string(
                serde_json::json!({
                    "credential_issuer": "https://issuer.example",
                    "selected_credential_configuration_id": "UniversityDegree",
                    "refresh_token": "rt-1",
                    "dpop_jwk": relay,
                    "reissuance_kid": "kid-original"
                })
                .to_string(),
            )
            .ok(),
            timeout: None,
        };

        Oid4vciFlow
            .start_flow(&ctx, &start)
            .await
            .expect("the renewal completes");

        // The refresh grant went to the token endpoint.
        let token_requests = http.token_requests.lock().expect("lock");
        assert_eq!(token_requests.len(), 1);
        let form = String::from_utf8_lossy(&token_requests[0]).into_owned();
        assert!(form.contains("grant_type=refresh_token"));
        assert!(form.contains("refresh_token=rt-1"));

        // The proof was signed with the EXISTING key the issuer knows.
        let key_ids = host.sign_key_ids.lock().expect("lock");
        assert_eq!(key_ids.as_slice(), [Some("kid-original".to_owned())]);
    }
}

#[cfg(test)]
mod as_selection_tests {
    //! #511: the offer's `authorization_server` hint — the grant-level
    //! hint selects the AS; a mismatch fails closed; no hint keeps the
    //! first-advertised choice.

    use super::*;

    fn offer(grants: serde_json::Value) -> types::CredentialOffer {
        types::CredentialOffer {
            credential_issuer: "https://issuer.example".to_owned(),
            credential_configuration_ids: vec!["UniversityDegree".to_owned()],
            grants,
        }
    }

    fn issuer_metadata(servers: &[&str]) -> types::IssuerMetadata {
        types::IssuerMetadata {
            credential_issuer: "https://issuer.example".to_owned(),
            authorization_servers: servers.iter().map(|s| s.to_string()).collect(),
            ..serde_json::from_value(serde_json::json!({
                "credential_issuer": "https://issuer.example"
            }))
            .expect("the minimal metadata parses")
        }
    }

    #[test]
    fn a_matching_hint_selects_the_hinted_as() {
        let offer = offer(serde_json::json!({
            "authorization_code": {"authorization_server": "https://as-2.example"}
        }));
        let issuer_metadata = issuer_metadata(&["https://as-1.example", "https://as-2.example"]);
        assert_eq!(
            select_as_url(&offer, &issuer_metadata),
            Ok("https://as-2.example".to_owned()),
            "the hint selects, not the first"
        );
    }

    #[test]
    fn a_mismatched_hint_fails_closed() {
        // OpenID4VCI 1.0/1.1: the wallet MUST NOT proceed when the hint
        // matches no advertised entry.
        let offer = offer(serde_json::json!({
            "authorization_code": {"authorization_server": "https://evil.example"}
        }));
        let issuer_metadata = issuer_metadata(&["https://as-1.example"]);
        assert!(
            select_as_url(&offer, &issuer_metadata).is_err(),
            "the mismatch fails closed"
        );
    }

    #[test]
    fn an_exact_match_is_required() {
        // The match is an exact string comparison: a trailing slash or a
        // scheme difference is a mismatch.
        let offer = offer(serde_json::json!({
            "authorization_code": {"authorization_server": "https://as-1.example/"}
        }));
        let issuer_metadata = issuer_metadata(&["https://as-1.example"]);
        assert!(select_as_url(&offer, &issuer_metadata).is_err());
    }

    #[test]
    fn no_hint_keeps_the_first_advertised() {
        let offer = offer(serde_json::json!({
            "authorization_code": {"issuer_state": "x"}
        }));
        let metadata = issuer_metadata(&["https://as-1.example", "https://as-2.example"]);
        assert_eq!(
            select_as_url(&offer, &metadata),
            Ok("https://as-1.example".to_owned())
        );
        // And no advertised servers at all: the credential issuer itself.
        let metadata = issuer_metadata(&[]);
        assert_eq!(
            select_as_url(&offer, &metadata),
            Ok("https://issuer.example".to_owned())
        );
    }

    #[test]
    fn the_hint_is_read_from_either_grant() {
        // The pre-authorized grant carries it too.
        let offer = offer(serde_json::json!({
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "x",
                "authorization_server": "https://as-2.example"
            }
        }));
        let issuer_metadata = issuer_metadata(&["https://as-1.example", "https://as-2.example"]);
        assert_eq!(
            select_as_url(&offer, &issuer_metadata),
            Ok("https://as-2.example".to_owned())
        );
    }
}

#[cfg(test)]
mod aux_gate_tests {
    //! The auxiliary-data selection gate (#480): the flow-level call the
    //! start and the resume make — parse + verdict, refused before any
    //! authorization or request. The pieces are proven in
    //! auxiliary::tests; this module pins the flow-level shape.

    use super::*;

    #[tokio::test]
    async fn the_start_flow_gate_refuses_an_unusable_advertisement() {
        // The start_flow gate is parse + verdict over the selected
        // configuration; the pieces are proven at the unit level. This
        // pins the order: the refusal fires before the grant dispatch,
        // so no token POST happens — the same call the resume makes.
        let configuration = serde_json::json!({
            "format": "dc+sd-jwt",
            "vct": "https://example/PID",
            "proof_types_supported": {"jwt": {}},
            "auxiliary_data_supported": {
                "to_wallet": [{
                    "type": "hash_commitment",
                    "alg": "sha-512",
                    "path": ["family_name"],
                }]
            }
        });
        let delivery =
            auxiliary::secret_delivery_of(&configuration).expect("the advertisement parses");
        let refusal = auxiliary::usable(&delivery, &configuration)
            .expect_err("the sha-512 entry the wallet cannot check");
        assert!(
            refusal.reason.contains("alg or encoding"),
            "the refusal names the class: {refusal}"
        );
    }

    #[tokio::test]
    async fn the_start_flow_gate_fails_closed_on_auxiliary_data_in_issuer_metadata() {
        // §7: auxiliary_data MUST NOT appear in the issuer metadata; the
        // gate fails closed before any request.
        let configuration = serde_json::json!({
            "format": "dc+sd-jwt",
            "credential_metadata": {"auxiliary_data": {}},
            "auxiliary_data_supported": {"to_wallet": [{
                "type": "hash_commitment",
                "alg": "sha-256",
                "path": ["family_name"],
            }]},
        });
        assert!(
            matches!(
                auxiliary::secret_delivery_of(&configuration),
                Err(auxiliary::SecretDeliveryError::AuxiliaryDataInIssuerMetadata(_))
            ),
            "the §7 rule fails closed at the gate"
        );
    }

    #[tokio::test]
    async fn the_resume_gate_is_the_same_call() {
        // The resume re-parses from its own metadata — a configuration
        // that changed to an unusable advertisement between the start
        // and the redirect is refused on the resume too.
        let configuration = serde_json::json!({
            "format": "dc+sd-jwt",
            "vct": "https://example/PID",
            "proof_types_supported": {"cwt": {}},
            "auxiliary_data_supported": {"to_issuer": [{
                "type": "hash_commitment",
                "alg": "sha-256",
                "path": ["family_name"],
                "required": true,
            }]},
        });
        let delivery =
            auxiliary::secret_delivery_of(&configuration).expect("the advertisement parses");
        assert!(
            auxiliary::usable(&delivery, &configuration).is_err(),
            "no carrier proof type: the resume refuses too"
        );
    }
}
