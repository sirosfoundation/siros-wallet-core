//! The issuer entitlement check (ARF 6.6.2.3): is the provider registered
//! to issue what it offers — a question distinct from trust (a trusted
//! issuer can still be unregistered), evaluated through the PDP port.
//!
//! The check runs after the trust decision, before the grant dispatch
//! (the flow start and the authorization-code resume): the findings ride
//! an additive `trust_evaluated` progress that deliberately does not set
//! `issuer_trust_evaluated` — the SDKs key their trust report on that
//! member, so the findings can never read as a trust decision — and a
//! refusal answers `-31020` with the bounded decision.
//!
//! The evaluation is the PDP implementation's (the backend adapter's —
//! the WRPAC/WRPRC parsing lives with the trust stack, `go-trust`'s
//! rpcert, not the wallet core); the mode lives there too, and its
//! answer already carries it. A PDP that does not implement the
//! operation answers "not evaluated", and the flow proceeds — the ARF's
//! 24-month grace.

use engine_ports::EntitlementDecision;

use crate::runtime::FlowContext;

use super::trust;
use super::types::IssuerMetadata;

/// Runs the entitlement check for a flow: builds the request from the
/// resolved metadata and the offer, calls the PDP, and shapes the
/// outcomes — the additive findings progress, and the decision the
/// caller refuses on (`!allowed` answers `-31020` through
/// [`not_entitled_data`]).
///
/// The check is additive by design: a PDP that answers nothing — the
/// operation unimplemented, the evaluator unreachable or erroring —
/// leaves the decision "not evaluated" and the flow proceeds. The mode
/// is the evaluator's, so a deployment that wants the check to fail
/// closed answers `allowed: false` itself; and a broken PDP already
/// refused the flow at the trust decision, which fails closed. Never
/// both a trust refusal and an entitlement refusal for one flow: the
/// trust refusal answers first.
pub async fn check_entitlement(
    ctx: &FlowContext,
    issuer: &str,
    metadata: &IssuerMetadata,
    configuration_ids: &[String],
) -> EntitlementDecision {
    // The offers: the configurations the flow is about to request, in
    // the evaluator's terms (the format identifier and the type). What
    // can be selected is what is checked — the ids the selection
    // accepts, not a second reading of the raw document.
    let offers = offers_of(metadata, configuration_ids);

    let request = engine_ports::EntitlementRequest {
        issuer: issuer.to_owned(),
        // The raw document: the evaluator reads the members the core
        // does not model (the `issuer_info` registration certificate)
        // from it, as the Go evaluator does.
        metadata: metadata.raw.clone(),
        // The signing chain, as the trust decision received it: the
        // WRPAC the check reads is the chain that signed the document.
        key_material: trust::extract_key_material(metadata),
        offers,
    };

    let decision = match ctx.pdp().evaluate_entitlement(request).await {
        Ok(decision) => decision,
        // No answer is no evaluation: nothing was checked, nothing
        // refused (ARF 6.6.2.3's 24-month grace — a minimal PDP keeps
        // every flow working).
        Err(_) => engine_ports::entitlement_not_evaluated(),
    };

    // The findings progress: additive to the issuer trust report.
    // Deliberately not setting `issuer_trust_evaluated`, which the
    // SDKs key their trust report on, so it can never be read as a
    // trust decision. It carries no `trust_info`. The bounded decision
    // rides it, whatever the evaluator returned.
    if !decision.findings.is_empty() || decision.findings_truncated {
        let bounded = decision.bounded();
        // A progress the transport refuses does not refuse the flow:
        // the findings ride the refusal's data too.
        let _ = ctx
            .progress(
                "trust_evaluated",
                &serde_json::json!({
                    "issuer_entitlement_evaluated": true,
                    "issuer": issuer,
                    "issuer_entitlement": {
                        "allowed": bounded.allowed,
                        "mode": bounded.mode.as_str(),
                        "evaluated": bounded.evaluated,
                        "findings": bounded.findings.iter().map(|f| serde_json::json!({
                            "code": f.code.as_str(),
                            "message": f.message,
                            "credential_type": f.credential_type,
                        })).collect::<Vec<_>>(),
                        "findings_truncated": bounded.findings_truncated,
                    },
                }),
            )
            .await;
    }

    decision
}

/// The refusal: `-31020` (`wmp.ErrIssuerNotEntitled`) with the bounded
/// decision as its data — the issuer and the same bounded summary the
/// findings progress carries.
#[must_use]
pub fn not_entitled_data(
    issuer: &str,
    decision: &EntitlementDecision,
) -> wmp_core::error::RpcError {
    let bounded = decision.bounded();
    wmp_core::error::RpcError::new(
        wmp_core::error::ERR_ISSUER_NOT_ENTITLED,
        Some(serde_json::json!({
            "issuer": issuer,
            "issuer_entitlement": {
                "allowed": bounded.allowed,
                "mode": bounded.mode.as_str(),
                "evaluated": bounded.evaluated,
                "findings": bounded.findings.iter().map(|f| serde_json::json!({
                    "code": f.code.as_str(),
                    "message": f.message,
                    "credential_type": f.credential_type,
                })).collect::<Vec<_>>(),
                "findings_truncated": bounded.findings_truncated,
            },
        })),
    )
}

/// The evaluator's offers from the selected configurations: the format
/// identifier and the type each declares.
///
/// The type discriminator is chosen by the format, as the credential
/// request will be: `doctype` for `mso_mdoc`, `vct` for the SD-JWT VCs —
/// reading "whichever field is set" would let a configuration carry a
/// registered value in the field its format ignores and an unregistered
/// one in the field that counts (the Go evaluator's `OfferFor`, which
/// `provider_is_entitled` is expressed in). An id that is not in the
/// metadata cannot be selected, so it is skipped.
fn offers_of(
    metadata: &IssuerMetadata,
    configuration_ids: &[String],
) -> Vec<engine_ports::EntitlementOffer> {
    configuration_ids
        .iter()
        .filter_map(|id| {
            let config = metadata
                .credential_configurations
                .as_object()?
                .get(id.as_str())?;
            let format = config
                .get("format")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let vct = config
                .get("vct")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let doctype = config
                .get("doctype")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            // The type by the format: mso_mdoc reads its doctype, the
            // SD-JWT formats their vct; an unknown format falls back to
            // the vct, then the doctype.
            let credential_type = match format.as_str() {
                "mso_mdoc" => doctype,
                "dc+sd-jwt" | "vc+sd-jwt" => vct,
                _ if !vct.is_empty() => vct,
                _ => doctype,
            }
            .to_owned();
            Some(engine_ports::EntitlementOffer {
                format,
                credential_type,
            })
        })
        .collect()
}
