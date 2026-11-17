//! The credential configuration selection (the Go engine's
//! `selectCredentialConfigurations`): WHICH of the offer's configurations
//! the wallet issues — the selected SET (#28 / go-wallet-backend#549,
//! Platform-Epics#63).
//!
//! Three sources, in order:
//!
//! 1. **The flow-start set** — the wallet that already chose names its
//!    subset in `selected_credential_configuration_ids` on the flow
//!    start (a picker UI ahead of the flow). It IS the selection: no
//!    ask runs, whatever the policy (the user already chose).
//! 2. **`issue_all` (the default)** — every offered configuration
//!    issues, with no selection step at all.
//! 3. **`user_selects`** — the `awaiting_selection` progress with the
//!    `available_credentials` the selection UI shows, then the host's
//!    answer: a SET (a subset of the offer — one, several, or all; the
//!    legacy single-id answer stays accepted as a one-element set).
//!
//! Exactly one resolvable configuration auto-selects under every mode:
//! no progress, no ask (a single-configuration offer is not a choice).
//!
//! Every answer is constrained to the offer's configurations — a
//! stronger rule than the Go engine's (which accepts any id the
//! issuer metadata defines): the entitlement check (ARF 6.6.2.3)
//! evaluated the *offered* configurations, so what is issued must be
//! what was checked — a selection the offer never named cannot reach
//! the credential request (see `oid4vci::entitlement`, whose contract
//! "the selection accepts nothing else" this is). The offer's order
//! and de-duplication apply to every answer: the answer's own order
//! is not a sorting instruction.

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

/// Who selects the set when the flow start named none: the #549/#28
/// modes. `issue_all` (the default) issues every offered configuration
/// with no selection step at all; `user_selects` keeps the
/// `awaiting_selection` progress + the host's ask, answered with a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SelectionPolicy {
    /// Every offered configuration issues — no ask (the default).
    #[default]
    IssueAll,
    /// The user's choice, asked through the host after the
    /// `awaiting_selection` progress.
    UserSelects,
}

impl SelectionPolicy {
    /// Parses the flow start's `issuance_selection_policy` member: an
    /// unrecognized value becomes the issue_all default rather than a
    /// refusal, so a typo cannot break a flow the user already chose
    /// nothing in — the offer's own semantics decide.
    #[must_use]
    pub fn parse(configured: Option<&str>) -> Self {
        match configured {
            Some("user_selects") => Self::UserSelects,
            _ => Self::IssueAll,
        }
    }
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

/// The selection's answer: the selected SET of configuration ids, or
/// the refusal.
#[derive(Debug)]
pub struct Selection {
    /// The selected configuration ids, in the offer's order,
    /// de-duplicated — every one present in the issuer metadata.
    pub configuration_ids: Vec<String>,
}

/// The offer-ordered, de-duplicated subset of the offer's ids: every
/// id must be one the offer put on the table (offered AND resolvable —
/// an offered id the metadata never defined cannot be selected), and
/// the answer's own order is not a sorting instruction.
fn ordered_subset(
    metadata: &IssuerMetadata,
    offer_ids: &[String],
    answer: &[String],
) -> Result<Vec<String>, SelectionError> {
    let available = available_of(metadata, offer_ids);
    let offered: rustc_hash::FxHashSet<&str> = available.iter().map(|a| a.id.as_str()).collect();
    if answer.is_empty() || answer.iter().any(|id| !offered.contains(id.as_str())) {
        return Err(SelectionError::Invalid);
    }
    let mut seen = rustc_hash::FxHashSet::default();
    let ordered = offer_ids
        .iter()
        .filter(|id| offered.contains(id.as_str()) && answer.contains(id))
        .filter(|id| seen.insert(id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if ordered.is_empty() {
        return Err(SelectionError::Invalid);
    }
    Ok(ordered)
}

/// Selects the configurations to issue, for one offer (#28): the
/// flow-start set when the wallet named one (the user already chose —
/// no ask, whatever the policy); else exactly one resolvable
/// configuration auto-selects; else the policy — every offered
/// configuration under `issue_all` (the default), or the user's
/// subset asked through the host under `user_selects`.
///
/// Every answer is constrained to the offer (see the module docs):
/// what is issued is what the entitlement check evaluated. A host
/// that cannot answer — the default `request_credential_selection`
/// an older host inherits — refuses the same way, so a
/// multi-configuration offer on an old host fails closed under
/// `user_selects` rather than issuing configurations unasked.
pub async fn select_configurations(
    ctx: &FlowContext,
    flow_id: &str,
    metadata: &IssuerMetadata,
    offer_ids: &[String],
    pre_selected: &[String],
    policy: SelectionPolicy,
) -> Result<Selection, SelectionError> {
    // 1. The flow-start set: the wallet that already chose. It IS the
    // selection — no ask runs, whatever the policy.
    if !pre_selected.is_empty() {
        let configuration_ids = ordered_subset(metadata, offer_ids, pre_selected)?;
        return Ok(Selection { configuration_ids });
    }

    let available = available_of(metadata, offer_ids);

    // Exactly one: auto-selected, no progress, no ask (the Go rule) —
    // under every mode.
    if let [only] = available.as_slice() {
        return Ok(Selection {
            configuration_ids: vec![only.id.clone()],
        });
    }

    // 2. issue_all (the default): every offered configuration, no ask.
    if policy == SelectionPolicy::IssueAll {
        return Ok(Selection {
            configuration_ids: available.into_iter().map(|a| a.id).collect(),
        });
    }

    // 3. user_selects: the `awaiting_selection` progress the
    // consumers' UI state machine keys on (docs/engine-parity.md §2),
    // then the host's answer — a SET.
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
            // configurations unasked.
            HostError::Cannot(_) => SelectionError::Invalid,
        })?;

    // The answer's set (the plural member; the legacy single member is
    // the one-element set), constrained to the offer, offer-ordered.
    let configuration_ids = ordered_subset(metadata, offer_ids, &answer.ids())?;
    Ok(Selection { configuration_ids })
}
