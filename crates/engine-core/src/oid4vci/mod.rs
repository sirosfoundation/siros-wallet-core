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
pub mod entitlement;
pub mod issuer;
pub mod nonce;
pub mod notification;
pub mod offer;
pub mod selection;
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

        // ── The issuer entitlement check (ARF 6.6.2.3): is the provider
        // registered to issue what it offers — a question distinct from
        // the trust decision above, so it runs in addition to it, never
        // instead of it. The configurations checked are the offer's —
        // the selection accepts nothing else, so what is issued is what
        // was checked. A refusal answers -31020; the findings ride the
        // additive progress inside the check.
        let entitlement = entitlement::check_entitlement(
            ctx,
            &offer.credential_issuer,
            &issuer_metadata,
            &offer.credential_configuration_ids,
        )
        .await;
        if !entitlement.allowed {
            return Err(HandlerError::Rpc(entitlement::not_entitled_data(
                &offer.credential_issuer,
                &entitlement,
            )));
        }

        // ── The credential configuration selection — the SET (#28 /
        // go-wallet-backend#549, Platform-Epics#63): which of the
        // offer's configurations the wallet issues. Three sources, in
        // order (see selection.rs): the flow-start set
        // (`selected_credential_configuration_ids` — the subset the
        // user already chose; no ask runs, whatever the policy), the
        // issue_all default (every offered configuration, no ask), or
        // the user_selects ask (`awaiting_selection` + the host's
        // answer, a SET). Every answer is constrained to the offer:
        // what is issued is what the entitlement check above
        // evaluated. The selection runs BEFORE any authorization or
        // request, so the credential request names the selected set.
        let pre_selected: Vec<String> = offer_params
            .get("selected_credential_configuration_ids")
            .and_then(|v| v.as_array())
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| id.as_str())
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let policy = selection::SelectionPolicy::parse(
            offer_params
                .get("issuance_selection_policy")
                .and_then(|v| v.as_str()),
        );
        let selection = selection::select_configurations(
            ctx,
            &params.flow_id,
            &issuer_metadata,
            &offer.credential_configuration_ids,
            &pre_selected,
            policy,
        )
        .await
        .map_err(|err| match err {
            selection::SelectionError::Declined => {
                flow_error("the user declined the selection".to_owned())
            }
            selection::SelectionError::Invalid => {
                flow_error("invalid credential configuration".to_owned())
            }
        })?;
        let configuration_ids = selection.configuration_ids;

        // ── The auxiliary-data selection gate (Credential Auxiliary
        // Data v0.1, #480) runs PER CONFIGURATION inside the issuance
        // loop (issue_the_set): the advertisement is read from each
        // selected configuration before its request — an entry the
        // wallet cannot handle (a to_wallet alg/encoding, a required
        // to_issuer entry) or a malformed advertisement fails that
        // configuration's issuance (reported, never aborting the
        // others), and the engine never handles a secret value: the
        // gate reads the advertisement alone.

        // ── S2: negotiate the response encryption, when the issuer supports it
        // The alg/enc pair from the issuer's credential_response_encryption
        // metadata, in preference order (A256GCM first). The key the wallet
        // offers goes in the credential request's
        // credential_response_encryption member. When the issuer required
        // encryption and no pair overlaps, the flow refuses — there is no
        // compliant way to request the credential.
        // #53: pre-selection, so only the issuer-level member (the Final
        // §12.2.4 shape) can be read here; a per-credential override is
        // the selected configuration's, read in the issuance loop.
        let negotiated_encryption = negotiated_encryption_for(&issuer_metadata, None);
        if let (Some(config), None) = (
            encryption_config_for(&issuer_metadata, None),
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

        let (_token, issued, failures) = if let Some(refresh) = &renewal_token {
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

            // The selected set (the selection above), not a second
            // reading of the offer — a renewal's set is the one
            // configuration its synthetic offer named.
            let (issued, failures) = issue_the_set(
                ctx,
                &params.flow_id,
                &issuer_metadata,
                &token,
                &configuration_ids,
                dpop_key.as_ref(),
                dpop_key_id.as_deref(),
                reissuance_kid.as_deref(),
            )
            .await?;

            (Some(token), issued, failures)
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

            // The selected set (the selection above): one token
            // authorizes the whole set — #549's motivating case (one
            // pre-authorized code, every offered configuration).
            let (issued, failures) = issue_the_set(
                ctx,
                &params.flow_id,
                &issuer_metadata,
                &token,
                &configuration_ids,
                dpop_key.as_ref(),
                dpop_key_id.as_deref(),
                reissuance_kid.as_deref(),
            )
            .await?;

            (Some(token), issued, failures)
        } else if offer.grants.get("authorization_code").is_some() {
            // ── The authorization-code grant: PKCE, PAR, the
            // authorization URL, and the handoff. The flow continues in
            // handle_action when the redirect returns with the code.
            let authorization = start_authorization_code(
                ctx,
                &params.flow_id,
                &CodeGrantStart {
                    offer_params: &offer_params,
                    offer: &offer,
                    as_metadata: &as_metadata,
                    issuer_metadata: &issuer_metadata,
                    configuration_ids: &configuration_ids,
                    dpop_key_id: dpop_key_id.as_deref(),
                },
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

        // Report the flow completion: every issued configuration's
        // result (#28 — the SET, one `credentials` entry per
        // configuration, each paired with its configuration id), the
        // per-configuration failures when some did not issue, and the
        // renewal relay (the refresh token, and the DPoP key material
        // it must be reused with: a renewal presents the engine-held
        // key as `dpop_jwk` — the next flow may land on another engine
        // instance; the client-held key needs no relay, the host knows
        // its own key id). The notification contexts (#527) were
        // registered per response inside the loop — the completion
        // carries each entry's own notification members, plus the
        // legacy single-configuration members of the first (the Go
        // CompleteWithRefreshToken).
        let completion =
            issuance_completion(&issued, &failures, _token.as_ref(), dpop_key.as_ref());
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
    /// The client-held DPoP key the start named (`dpop_key_id`) — the resume
    /// re-threads it into the token exchange so the DPoP proof the host
    /// signs rides the SAME key the WIA attests (EC TS03's one-key rule, the
    /// Go engine's client-held mode). Found driving the GDC issuance: the
    /// resume asked dpop_proof with no key, the host answered empty, and the
    /// engine DPoP'd with its own ephemeral key — the AS answered
    /// invalid_dpop_proof.
    dpop_key_id: Option<String>,
    /// The selected credential configuration — the user's choice, made
    /// before the redirect: the resume requests the same one, never a
    /// re-derivation (and never a second ask) after the browser
    /// roundtrip. The pre-#28 single member: a stash an older engine
    /// wrote still resumes (as the one-element set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    configuration_id: Option<String>,
    /// The selected credential configurations — the SET (#28): the
    /// resume requests the same set, never a re-derivation (and never
    /// a second ask) after the browser roundtrip.
    #[serde(default)]
    configuration_ids: Vec<String>,
    /// The original offer params, as the flow start received them — the
    /// resume re-parses the offer from this (the stateless resume).
    offer_params: serde_json::Value,
    /// The AS selected for the ORIGINAL transaction (its metadata's
    /// `issuer`): the RFC 9207 `iss` the resume receives is compared
    /// against exactly this (the #551 rule — the AS can differ from the
    /// credential issuer), and the re-resolved AS must be the same one.
    #[serde(default)]
    as_issuer: String,
    /// Whether the original AS advertised
    /// `authorization_response_iss_parameter_supported`: stashed at the
    /// start so a metadata refresh cannot drop the requirement between
    /// the start and the resume.
    #[serde(default)]
    as_iss_supported: Option<bool>,
}

/// The KeyValue key the authorization-code flow stashes under.
fn stash_key(flow_id: &str) -> String {
    format!("oid4vci:auth-code:{flow_id}")
}

impl AuthorizationStash {
    /// The stash's selected set: the plural member (#28), else the
    /// legacy single member as the one-element set (a stash an older
    /// engine wrote).
    fn selected_ids(&self) -> Vec<String> {
        if !self.configuration_ids.is_empty() {
            return self.configuration_ids.clone();
        }
        self.configuration_id
            .as_ref()
            .map(|id| vec![id.clone()])
            .unwrap_or_default()
    }
}

/// The authorization-code grant's start inputs: the offer the wallet
/// passed (its raw params and their parse), the AS and issuer metadata
/// the flow resolved, the configuration the selection named, and the
/// client-held DPoP key the start named (`dpop_key_id`: stashed for the
/// resume - the redirect's answer rides the action - so the resume's
/// token exchange asks the host to DPoP with the SAME key the WIA
/// attests, EC TS03's one-key rule; found driving - see the stash field).
/// Bundled because they travel together from the one call site.
struct CodeGrantStart<'a> {
    offer_params: &'a serde_json::Value,
    offer: &'a types::CredentialOffer,
    as_metadata: &'a types::AsMetadata,
    issuer_metadata: &'a types::IssuerMetadata,
    configuration_ids: &'a [String],
    dpop_key_id: Option<&'a str>,
}

/// Builds the authorization request for the authorization_code grant:
/// the PKCE pair and the OAuth state from the Rng port, the assembled
/// parameters (auth_params), PAR when the AS advertises it (with the
/// required-PAR no-fallback rule), and the stash for the resume.
async fn start_authorization_code(
    ctx: &FlowContext,
    flow_id: &str,
    start: &CodeGrantStart<'_>,
) -> Result<AuthorizationHandoff, HandlerError> {
    let offer_params = start.offer_params;
    let offer = start.offer;
    let as_metadata = start.as_metadata;
    let issuer_metadata = start.issuer_metadata;
    let configuration_ids = start.configuration_ids;
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

    // The selected SET's joined scope (#28): every distinct scope
    // value of the selected configurations, de-duplicated, in the
    // offer's order, space-delimited (RFC 6749 §3.3) — one
    // authorization, one token, for the whole set. The selection's
    // choice, not a re-derivation from the offer.
    let scope = joined_scope_of(issuer_metadata, configuration_ids);
    let scope = scope.as_deref();

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
        dpop_key_id: start.dpop_key_id.map(str::to_owned),
        configuration_id: None,
        configuration_ids: configuration_ids.to_vec(),
        offer_params: offer_params.clone(),
        // The AS selected for THIS transaction (#551's rule): the resume's
        // `iss` comparison binds to it — which can differ from the
        // credential issuer — and the re-resolved AS must be the same one.
        as_issuer: as_metadata.issuer.clone(),
        // Whether the AS advertised the `iss` requirement — the resume
        // re-resolves the metadata, but the STASHED decision holds: a
        // metadata refresh that drops the member cannot downgrade the
        // check between the start and the resume (the #551 rule).
        as_iss_supported: as_metadata.authorization_response_iss_supported,
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

    // The entitlement check, again, on the resume (ARF 6.6.2.3): the
    // same additive question after the same fail-closed trust
    // re-evaluation. The stashed offer's configurations are what the
    // resumed flow requests.
    let entitlement = entitlement::check_entitlement(
        ctx,
        &offer.credential_issuer,
        &issuer_metadata,
        &offer.credential_configuration_ids,
    )
    .await;
    if !entitlement.allowed {
        return Err(HandlerError::Rpc(entitlement::not_entitled_data(
            &offer.credential_issuer,
            &entitlement,
        )));
    }

    // #511: the hint selects the AS on the resume path too.
    let as_url = select_as_url(&offer, &issuer_metadata).map_err(flow_error)?;
    let as_metadata = as_metadata::discover_as_metadata(ctx.http().as_ref(), &as_url, false)
        .await
        .map_err(|err| flow_error(err.to_string()))?;

    // The RFC 9207 issuer check (#551's rule, the FAPI2
    // remove-authorization-response-iss conformance case): the response
    // `iss` is validated BEFORE the code is exchanged, against the AS
    // selected for the ORIGINAL transaction (the stash's - the AS can
    // differ from the credential issuer). Required when the original AS
    // advertised `authorization_response_iss_parameter_supported` (the
    // stashed decision: a metadata refresh that drops the member cannot
    // downgrade the check between the start and the resume) or the
    // deployment knob demands it (FAPI enforcement without advertised
    // support). A supplied `iss` is always compared, never required
    // alone. Malformed shapes (null, not a string) are refused, never
    // read as absent - the same fail-closed rule the whole resume runs
    // on. Duplicate URL parameters are the CALLBACK parser's to reject
    // (the frontend/SDK reduces them; by here they are one JSON member).
    let iss = match action_params.get("iss") {
        None => None,
        Some(value) => match value.as_str() {
            Some(iss) => Some(iss),
            None => {
                return Err(flow_error(
                    "the authorization response's iss is not a string (RFC 9207)".to_owned(),
                ));
            }
        },
    };
    let iss_required =
        stash.as_iss_supported == Some(true) || ctx.ports.require_authorization_response_issuer;
    if iss_required && iss.is_none() {
        return Err(flow_error(
            "the authorization response carries no iss (RFC 9207) and the authorization server requires it"
                .to_owned(),
        ));
    }
    if let Some(iss) = iss {
        if iss != stash.as_issuer {
            return Err(flow_error(
                "the authorization response's issuer does not match the authorization server of the original transaction (RFC 9207)"
                    .to_owned(),
            ));
        }
    }
    // The re-resolved AS must be the ORIGINAL transaction's AS: a
    // metadata refresh that moved the issuer between the start and the
    // resume is a different transaction, not the one the user
    // authorized.
    if as_metadata.issuer != stash.as_issuer {
        return Err(flow_error(
            "the authorization server resolved on the resume is not the one selected for the original transaction"
                .to_owned(),
        ));
    }

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
            dpop_key_id: stash.dpop_key_id.as_deref(),
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

    // The response-encryption required-no-overlap refusal, as at the
    // flow start: an issuer that required encryption the wallet cannot
    // satisfy fails every configuration, so the flow fails fast with
    // the one error (the per-configuration requests inside the loop
    // negotiate their own fresh keys).
    // #53: pre-selection (the stash carries the ids; the configurations
    // are re-resolved per id inside the loop), so only the issuer-level
    // member is read here.
    if let (Some(config), None) = (
        encryption_config_for(&issuer_metadata, None),
        negotiated_encryption_for(&issuer_metadata, None).as_ref(),
    ) {
        if config.required {
            return Err(flow_error(
                encryption::EncryptionError::NoOverlap.to_string(),
            ));
        }
    }

    // The selected SET, as the stash carried it across the redirect —
    // the user's choice before the authorization, not a re-derivation
    // (and never a second ask) after the browser roundtrip. A stash an
    // older (pre-#28) engine wrote carries the single member and
    // resumes as the one-element set.
    let configuration_ids = stash.selected_ids();

    // The issuance loop (#28): the per-configuration auxiliary-data
    // gate (#480), a fresh response-encryption key per request, and
    // the credential request per selected configuration — the stash's
    // client-held DPoP key id threading inside (the AS bound the token
    // to it, so the credential request's DPoP proof must ride the SAME
    // key — a fresh engine-held key answers "DPoP key does not match
    // the key bound to the access token"; found driving the GDC
    // issuance, 2026-11-07). The resume's exchange signs engine-held,
    // so the client-held key id does not survive the round trip.
    let (issued, failures) = issue_the_set(
        ctx,
        &params.flow_id,
        &issuer_metadata,
        &token,
        &configuration_ids,
        dpop_key.as_ref(),
        stash.dpop_key_id.as_deref(),
        None,
    )
    .await?;

    // The completion carries every issued configuration's result and
    // the renewal relay, exactly as the start_flow path does — the
    // notification contexts (#527) registered per response inside the
    // loop, so a wallet that finished its issuance over the
    // authorization-code round trip can notify too.
    let completion = issuance_completion(&issued, &failures, Some(&token), dpop_key.as_ref());
    let _ = ctx.complete(&completion).await;

    Ok(FlowActionResult {
        wmp: wmp_core::types::Metadata::default(),
        flow_id: params.flow_id.clone(),
        action: params.action.clone(),
        status: "completed".to_owned(),
    })
}

/// The issuer's `credential_response_encryption` configuration, when any
/// is published ([#53]).
///
/// OpenID4VCI 1.0 **Final §12.2.4** publishes the member at the
/// **issuer level** — beside `credential_configurations_supported`. The
/// per-credential placement (inside a configuration entry) is the
/// draft-era shape; when a selected configuration carries its own
/// member it **overrides** the issuer-level one for that
/// configuration, else the issuer-level member stands.
///
/// `configuration` is the selected configuration's JSON, when the
/// caller has one (`None` before a selection exists — the flow-start
/// probe — where only the issuer-level member can be read).
///
/// [#53]: https://github.com/sirosfoundation/siros-wallet-core/issues/53
fn encryption_config_for(
    issuer_metadata: &types::IssuerMetadata,
    configuration: Option<&serde_json::Value>,
) -> Option<encryption::ResponseEncryptionConfig> {
    // The per-configuration override (the draft-era shape): a
    // configuration carrying its own member decides its own encryption.
    let per_credential = configuration.and_then(|config| {
        config
            .get("credential_response_encryption")
            .cloned()
            .filter(|value| !value.is_null())
    });
    let raw = per_credential.or_else(|| {
        issuer_metadata
            .credential_response_encryption
            .clone()
            .filter(|value| !value.is_null())
    })?;
    serde_json::from_value::<encryption::ResponseEncryptionConfig>(raw).ok()
}

/// The negotiated response encryption with a fresh ephemeral key.
fn negotiated_encryption_for(
    issuer_metadata: &types::IssuerMetadata,
    configuration: Option<&serde_json::Value>,
) -> Option<encryption::NegotiatedResponseEncryption> {
    encryption_config_for(issuer_metadata, configuration)
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

// ─── The issuance loop (#28 / go-wallet-backend#549) ───────────────────────
//
// One token authorizes the whole selected set; each configuration gets
// its own proofs, credential request, deferred polling and completion
// entry — the SET semantics both engines converge on.

/// One configuration's issued credential: the response and the
/// notification members its registration produced.
struct IssuedCredential {
    configuration_id: String,
    response: credential::CredentialResponse,
    notification_members: serde_json::Value,
}

/// One configuration's failure, reported on the completion: WHICH
/// configuration did not issue, and why.
struct IssuanceFailure {
    configuration_id: String,
    reason: String,
}

/// The issuance loop over the SELECTED SET (#28): steps 6 to 9 per
/// configuration — the per-configuration auxiliary-data gate (#480), a
/// fresh response-encryption key per request, the host-signed proofs
/// (the FIRST keeps the reissuance kid; every other configuration
/// signs fresh — two proofs over the same key link the credentials,
/// the SDJWT-10.1 linkability rule), the credential request with the
/// invalid_nonce retry, the deferred polling, and the per-response
/// notification context (#527).
///
/// Partial failure: a configuration that fails does NOT abort the
/// others — its failure is collected and reported on the completion
/// (the `failures` member: which configuration, why), never sent as a
/// terminal error of its own. Zero successes is a failed flow: exactly
/// ONE error, the FIRST failure's reason — never one per
/// configuration.
///
/// Returns the issued credentials (each with its notification members)
/// and the failures; `Err` only when nothing issued at all.
#[allow(clippy::too_many_arguments)]
async fn issue_the_set(
    ctx: &FlowContext,
    flow_id: &str,
    issuer_metadata: &types::IssuerMetadata,
    token: &token::TokenResponse,
    configuration_ids: &[String],
    dpop_key: Option<&dpop::DpopKey>,
    dpop_key_id: Option<&str>,
    reissuance_kid: Option<&str>,
) -> Result<(Vec<IssuedCredential>, Vec<IssuanceFailure>), HandlerError> {
    let mut issued: Vec<IssuedCredential> = Vec::new();
    let mut failures: Vec<IssuanceFailure> = Vec::new();
    let mut first_reason: Option<String> = None;

    for (position, configuration_id) in configuration_ids.iter().enumerate() {
        let fail = |failures: &mut Vec<IssuanceFailure>,
                    first_reason: &mut Option<String>,
                    configuration_id: &str,
                    reason: String| {
            if first_reason.is_none() {
                *first_reason = Some(reason.clone());
            }
            failures.push(IssuanceFailure {
                configuration_id: configuration_id.to_owned(),
                reason,
            });
        };

        // The configuration, from the issuer metadata the selection
        // validated against — a selected id the metadata lacks is a
        // per-configuration failure (it cannot happen: the selection
        // only names resolvable ids).
        let Some(configuration) = issuer_metadata
            .credential_configurations
            .get(configuration_id)
            .cloned()
        else {
            fail(
                &mut failures,
                &mut first_reason,
                configuration_id,
                "the selected configuration is missing from the issuer metadata".to_owned(),
            );
            continue;
        };

        // The auxiliary-data selection gate, per configuration (#480):
        // the advertisement is read before the request — an entry the
        // wallet cannot handle or a malformed advertisement fails THIS
        // configuration's issuance, reported, never aborting the
        // others. The engine never handles a secret value: the gate
        // reads the advertisement alone.
        let delivery = match auxiliary::secret_delivery_of(&configuration) {
            Ok(delivery) => delivery,
            Err(err) => {
                // Nothing of the content in the reason.
                fail(
                    &mut failures,
                    &mut first_reason,
                    configuration_id,
                    format!("auxiliary_data_unsupported: {}", err.reason()),
                );
                continue;
            }
        };
        if let Err(refusal) = auxiliary::usable(&delivery, &configuration) {
            fail(
                &mut failures,
                &mut first_reason,
                configuration_id,
                format!("auxiliary_data_unsupported: {}", refusal.reason),
            );
            continue;
        }

        // A fresh response-encryption key per request: the ephemeral
        // key lives once, in the request that offers it.
        //
        // #51: the delivery plan — not the issuer's `encryption_required`
        // flag alone — decides the offer is MANDATORY. A `to_wallet`
        // `hash_commitment` carries a Secret Value (auxiliary.rs §7.1),
        // so the request must offer response encryption whether or not
        // the issuer asked for it; an issuer that yields no pair (or
        // advertises no `credential_response_encryption` at all) fails
        // THIS configuration's issuance before any request is made —
        // never the plain request the response-side gate would refuse
        // mid-flight (the realeyes repro: the request carried no
        // `credential_response_encryption` member, the issuer answered
        // plain carrying `auxiliary_data`, and the §7.1 gate refused
        // what the request side had made unavoidable).
        // #53: the SELECTED configuration rides along — its own
        // per-credential member (the draft-era shape) overrides the
        // issuer-level one for this configuration.
        let encryption_required = delivery.require_encryption
            || encryption_config_for(issuer_metadata, Some(&configuration))
                .as_ref()
                .is_some_and(|config| config.required);
        let negotiated_encryption =
            negotiated_encryption_for(issuer_metadata, Some(&configuration));
        if encryption_required && negotiated_encryption.is_none() {
            fail(
                &mut failures,
                &mut first_reason,
                configuration_id,
                match delivery.require_encryption {
                    true => encryption::EncryptionError::DeliveryRequiresNoPair.to_string(),
                    false => encryption::EncryptionError::NoOverlap.to_string(),
                },
            );
            continue;
        }

        // The FIRST configuration keeps the reissuance kid (a renewal's
        // same-key re-binding, ARF ISSU_65); every other signs fresh.
        let response = request_and_deliver(
            ctx,
            flow_id,
            issuer_metadata,
            token,
            configuration_id,
            DeliverParams {
                delivery: Some(&delivery),
                negotiated_encryption: negotiated_encryption.as_ref(),
                dpop_key,
                dpop_key_id,
                reissuance_kid: (position == 0).then_some(reissuance_kid).flatten(),
            },
        )
        .await;

        let response = match response {
            Ok(response) => response,
            Err(err) => {
                let reason = handler_error_reason(&err);
                fail(&mut failures, &mut first_reason, configuration_id, reason);
                continue;
            }
        };

        // The notification context (#527), per response: each id is
        // single use, and the wallet's later `credential_notification`
        // flows each name their own response's id.
        let notification_members = notification::register(
            ctx,
            flow_id,
            issuer_metadata,
            token,
            &response,
            dpop_key,
            dpop_key_id,
        );

        issued.push(IssuedCredential {
            configuration_id: configuration_id.clone(),
            response,
            notification_members,
        });
    }

    // Zero successes: a failed flow with exactly ONE error — the first
    // failure's reason (never one per configuration).
    if issued.is_empty() {
        return Err(HandlerError::Rpc(wmp_core::error::RpcError::new(
            wmp_core::error::ERR_FLOW_ERROR,
            Some(serde_json::json!({
                "reason": first_reason
                    .clone()
                    .unwrap_or_else(|| "credential issuance failed".to_owned()),
            })),
        )));
    }

    Ok((issued, failures))
}

/// A per-configuration failure's reason: the `reason` the error's data
/// carries, else the error's own text — reported on the completion, so
/// the wallet can tell the user which credential is missing and why.
fn handler_error_reason(err: &HandlerError) -> String {
    let HandlerError::Rpc(rpc) = err else {
        return err.to_string();
    };
    // The data is a raw JSON member: parse it to read the reason the
    // error's builder put there — the reason the completion's failures
    // report carries, never a sentence of the credential content.
    let Some(raw) = rpc.data.as_deref() else {
        return err.to_string();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw.get()) else {
        return err.to_string();
    };
    let reason = value.get("reason").and_then(|v| v.as_str());
    match (reason, value.get("detail").and_then(|v| v.as_str())) {
        (Some(reason), Some(detail)) => format!("{reason}: {detail}"),
        (Some(reason), None) => reason.to_owned(),
        (None, _) => err.to_string(),
    }
}

/// The flow completion over the selected set's outcome (#28): one
/// `credentials` entry per issued configuration — each paired with its
/// `credential_configuration_id` (the renewal pairing the single
/// member carried), its own notification members (#527) — and the
/// `failures` report when configurations did not issue. The legacy
/// single-configuration members (`credential`, `deferred`, the
/// flow-level notification members) keep the FIRST issued entry's
/// values, so a pre-#28 consumer of a single-configuration flow reads
/// the completion exactly as before.
fn issuance_completion(
    issued: &[IssuedCredential],
    failures: &[IssuanceFailure],
    token: Option<&token::TokenResponse>,
    dpop_key: Option<&dpop::DpopKey>,
) -> serde_json::Value {
    let credentials: Vec<serde_json::Value> = issued
        .iter()
        .map(|entry| {
            let mut object = serde_json::json!({
                "credential_configuration_id": entry.configuration_id,
                // The entry's format (go-wallet-backend messages.go's
                // `CredentialResult.Format` — always present, no omitempty;
                // issue #57): the SDK's batch decode (v0.23.5, the #419
                // parity) requires it with no default, so a member-less
                // entry refused every issuance as malformed after
                // `credential_received`.
                "format": entry.response.format.clone().unwrap_or_default(),
                "credential": entry.response.credential.clone().unwrap_or_default(),
                "deferred": entry.response.transaction_id.is_some(),
            });
            if let (Some(target), Some(members)) = (
                object.as_object_mut(),
                entry.notification_members.as_object(),
            ) {
                for (key, value) in members {
                    target.insert(key.clone(), value.clone());
                }
            }
            object
        })
        .collect();

    let mut completion = serde_json::json!({ "credentials": credentials });
    if let (Some(object), Some(first)) = (completion.as_object_mut(), issued.first()) {
        // The legacy single-configuration view: the first entry's.
        object.insert(
            "credential".to_owned(),
            serde_json::Value::String(first.response.credential.clone().unwrap_or_default()),
        );
        object.insert(
            "deferred".to_owned(),
            serde_json::Value::Bool(first.response.transaction_id.is_some()),
        );
        // The legacy flow-level notification members: the first
        // entry's.
        if let Some(members) = first.notification_members.as_object() {
            for (key, value) in members {
                object.insert(key.clone(), value.clone());
            }
        }
        // The renewal relay: the refresh token, and the DPoP key it
        // must be reused with (the next flow may land on another
        // engine instance).
        if let Some(refresh) = token.and_then(|t| t.refresh_token.clone()) {
            object.insert(
                "refresh_token".to_owned(),
                serde_json::Value::String(refresh),
            );
            if let Some(relay) = dpop_key.and_then(|key| key.private_jwk_json()) {
                object.insert("dpop_jwk".to_owned(), serde_json::Value::String(relay));
            }
        }
    }
    if !failures.is_empty() {
        if let Some(object) = completion.as_object_mut() {
            object.insert(
                "failures".to_owned(),
                serde_json::Value::Array(
                    failures
                        .iter()
                        .map(|failure| {
                            serde_json::json!({
                                "credential_configuration_id": failure.configuration_id,
                                "error": failure.reason,
                            })
                        })
                        .collect(),
                ),
            );
        }
    }
    completion
}

/// The selected set's joined scope (#28): every distinct scope value of
/// the selected configurations, de-duplicated, in the offer's order,
/// space-delimited (RFC 6749 §3.3) — one authorization, one token,
/// for the whole set.
fn joined_scope_of(metadata: &types::IssuerMetadata, ids: &[String]) -> Option<String> {
    let mut scopes: Vec<&str> = Vec::new();
    for id in ids {
        if let Some(scope) = metadata
            .credential_configurations
            .get(id)
            .and_then(|config| config.get("scope"))
            .and_then(|v| v.as_str())
            .filter(|scope| !scope.is_empty())
        {
            if !scopes.contains(&scope) {
                scopes.push(scope);
            }
        }
    }
    (!scopes.is_empty()).then(|| scopes.join(" "))
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
        // The running flow's id: the host asks (the signing key, the
        // credential proof) route their child flows by it.
        ctx.flow_id.as_str(),
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
