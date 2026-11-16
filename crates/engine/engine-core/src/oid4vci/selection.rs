//! The credential configuration selection (the Go engine's
//! `awaitCredentialSelection`): which of the offer's configurations
//! the wallet issues, when the offer names more than one — the user's
//! choice, asked through the host port.
//!
//! Exactly one resolvable configuration is auto-selected: no progress,
//! no ask (the Go rule — a single-configuration offer is not a
//! choice). More than one emits the `awaiting_selection` progress with
//! the `available_credentials` the selection UI shows, and asks the
//! host.
//!
//! The answer is constrained to the offer's configurations — a
//! stronger rule than the Go engine's (which accepts any id the
//! issuer metadata defines): the entitlement check (ARF 6.6.2.3)
//! evaluated the *offered* configurations, so what is issued must be
//! what was checked — a selection the offer never named cannot reach
//! the credential request (see `oid4vci::entitlement`, whose contract
//! "the selection accepts nothing else" this is).

use engine_ports::{AvailableCredential, CredentialSelectionParams, HostError};

use crate::runtime::FlowContext;

use super::types::IssuerMetadata;

/// Why a selection refused: the user declined, or the answer named no
/// configuration the offer put on the table.
#[derive(Debug, thiserror::Error)]
pub enum SelectionError {
    /// The host's user declined the offer.
    #[error("oid4vci: the user declined the credential selection")]
    Declined,
    /// The answer named no offered configuration, or the host cannot
    /// answer a selection ask at all (the default ask an older host
    /// inherits).
    #[error("oid4vci: invalid credential configuration")]
    Invalid,
}

/// The configurations the offer puts on the table, in the offer's
/// order, as the `awaiting_selection` progress and the selection ask
/// carry them: the id, the display, the format, the `vct`.
///
/// An offered id the metadata does not define is not on offer — the
/// issuer named a configuration it never published — and the ask never
/// presents it (it cannot be selected).
pub fn available_of(metadata: &IssuerMetadata, offer_ids: &[String]) -> Vec<AvailableCredential> {
    let configurations = metadata
        .credential_configurations
        .as_object()
        .map(|configs| {
            offer_ids
                .iter()
                .filter_map(|id| {
                    let config = configs.get(id.as_str())?;
                    Some(AvailableCredential {
                        id: id.clone(),
                        // The first display entry, raw: issuer-controlled
                        // display content, passed through for the
                        // selection UI to render (the core has no say on
                        // what gets said).
                        display: config
                            .get("display")
                            .and_then(|v| v.as_array())
                            .and_then(|entries| entries.first())
                            .cloned(),
                        format: config
                            .get("format")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_owned(),
                        vct: config
                            .get("vct")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_owned(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    configurations
}

/// The selection's answer: the chosen configuration's id and the
/// configuration itself, or the refusal.
#[derive(Debug)]
pub struct Selection {
    /// The chosen configuration's id.
    pub configuration_id: String,
    /// The chosen configuration, from the issuer metadata.
    pub configuration: serde_json::Value,
}

/// Selects the configuration to issue, for one offer: exactly one
/// resolvable configuration auto-selects; more than one is the user's
/// choice, asked through the host after the `awaiting_selection`
/// progress.
///
/// The answer must name one of the offered configurations (see the
/// module docs): an answer outside the offer refuses with
/// `invalid_credential_configuration`. A host that cannot answer — the
/// default `request_credential_selection` an older host inherits —
/// refuses the same way, so a multi-configuration offer on an old host
/// fails closed rather than issuing the first configuration.
pub async fn select_configuration(
    ctx: &FlowContext,
    flow_id: &str,
    metadata: &IssuerMetadata,
    offer_ids: &[String],
) -> Result<Selection, SelectionError> {
    let available = available_of(metadata, offer_ids);

    // Exactly one: auto-selected, no progress, no ask (the Go rule).
    if let [only] = available.as_slice() {
        let id = only.id.clone();
        let configuration = configuration_of(metadata, &id).unwrap_or(serde_json::Value::Null);
        return Ok(Selection {
            configuration_id: id,
            configuration,
        });
    }

    // The selection ask: the `awaiting_selection` progress the
    // consumers' UI state machine keys on (docs/engine-parity.md §2),
    // then the host's answer.
    let _ = ctx
        .progress(
            "awaiting_selection",
            &serde_json::json!({ "available_credentials": available }),
        )
        .await;

    let answer = ctx
        .host()
        .request_credential_selection(CredentialSelectionParams {
            flow_id: flow_id.to_owned(),
            available,
        })
        .await
        .map_err(|err| match err {
            // The user declined the offer itself.
            HostError::Declined => SelectionError::Declined,
            // A host that cannot answer: fail closed — never issue
            // the first configuration unasked.
            HostError::Cannot(_) => SelectionError::Invalid,
        })?;

    // The answer is constrained to the offer (the module docs): what
    // is issued is what the entitlement check evaluated.
    if !offer_ids.contains(&answer.credential_configuration_id) {
        return Err(SelectionError::Invalid);
    }
    let configuration = configuration_of(metadata, &answer.credential_configuration_id)
        .unwrap_or(serde_json::Value::Null);
    Ok(Selection {
        configuration_id: answer.credential_configuration_id,
        configuration,
    })
}

/// The configuration an id names, from the issuer metadata.
fn configuration_of(metadata: &IssuerMetadata, id: &str) -> Option<serde_json::Value> {
    metadata
        .credential_configurations
        .as_object()?
        .get(id)
        .cloned()
}
