//! The Mandate rulebook's metadata (Mandate §2): a wallet implementing it ships with every
//! claim, its position and its rendering, and labels them with its own texts. The credential's
//! metadata contributes its `security_hint`, shown exactly.

use std::borrow::Cow;

use siros_i18n::Message;
use siros_openid4vp::claims::{ClaimPath, Step};
use siros_openid4vp::json::Node;

use crate::labels::LabelLimits;
use crate::metadata::{
    ClaimMeta, DisplayArray, Displayed, EntryLocale, LabelForm, Localized, Mandatory, Metadata,
    UiKey, UiLabel, ValueType,
};
use crate::outcome::Unsupported;
use crate::value::{FormattedKind, ValueKind};

/// A label of the Mandate claims, by the screens of the rulebook's examples: a message of the
/// crate's module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Message)]
pub enum MandateLabel {
    /// The label of the claim `mandate_id`.
    #[message(id = "mandate.mandate_id")]
    MandateId,
    /// The label of the claims `mandatee.name` and `mandatee.logo`, which draws under it
    /// (Mandate A.2).
    #[message(id = "mandate.mandatee")]
    Mandatee,
    /// The label of the claim `action`.
    #[message(id = "mandate.action")]
    Action,
    /// The label of the claim `conditions`.
    #[message(id = "mandate.conditions")]
    Conditions,
    /// The label of the claim `max_amount`.
    #[message(id = "mandate.max_amount")]
    MaxAmount,
    /// The label of the claim `max_count`.
    #[message(id = "mandate.max_count")]
    MaxCount,
    /// The label of the claim `period`.
    #[message(id = "mandate.period")]
    Period,
    /// The label of the claim `valid_from`.
    #[message(id = "mandate.valid_from")]
    ValidFrom,
    /// The label of the claim `valid_until`.
    #[message(id = "mandate.valid_until")]
    ValidUntil,
    /// The label of the claim `payment_payload.amount`, which Payment A.1's metadata labels.
    #[message(id = "mandate.amount")]
    Amount,
    /// The label of the claim `payment_payload.payee.name`, which Payment A.1's metadata labels.
    #[message(id = "mandate.payee")]
    Payee,
    /// The label of the claim `payment_payload.payee.logo`, which Payment A.1's metadata labels.
    #[message(id = "mandate.payee_logo")]
    PayeeLogo,
}

impl MandateLabel {
    /// Every label.
    pub const ALL: [Self; 12] = [
        Self::MandateId,
        Self::Mandatee,
        Self::Action,
        Self::Conditions,
        Self::MaxAmount,
        Self::MaxCount,
        Self::Period,
        Self::ValidFrom,
        Self::ValidUntil,
        Self::Amount,
        Self::Payee,
        Self::PayeeLogo,
    ];
}

/// One row of Mandate §2's table: the path's first member and the members below it, whether it
/// is mandatory, its value type, its label (`None`: not displayed).
struct Row {
    first: &'static str,
    below: &'static [&'static str],
    mandatory: Mandatory,
    value: ValueType,
    label: Option<MandateLabel>,
}

const fn row(
    (first, below): (&'static str, &'static [&'static str]),
    mandatory: Mandatory,
    value: ValueType,
    label: Option<MandateLabel>,
) -> Row {
    Row {
        first,
        below,
        mandatory,
        value,
        label,
    }
}

const TEXT: ValueType = ValueType::Plain;
const IMAGE: ValueType = ValueType::Kind(ValueKind::Image);
const AMOUNT: ValueType = ValueType::Kind(ValueKind::Formatted(FormattedKind::CurrencyAmount));
const DATE: ValueType = ValueType::Kind(ValueKind::Formatted(FormattedKind::Date));
const MARKDOWN: ValueType = ValueType::Kind(ValueKind::Formatted(FormattedKind::MiniMarkdown));

/// Mandate §2's claims in table order, then §2.2's embedded payment with the Payment
/// rulebook's display semantics.
const TABLE: [Row; 19] = {
    use Mandatory::{No, Yes};
    [
        row(("transaction_id", &[]), No, TEXT, None),
        row(
            ("mandate_id", &[]),
            Yes,
            TEXT,
            Some(MandateLabel::MandateId),
        ),
        row(
            ("mandatee", &["name"]),
            Yes,
            TEXT,
            Some(MandateLabel::Mandatee),
        ),
        row(("mandatee", &["id"]), No, TEXT, None),
        row(
            ("mandatee", &["logo"]),
            No,
            IMAGE,
            Some(MandateLabel::Mandatee),
        ),
        row(("mandatee", &["logo#integrity"]), No, TEXT, None),
        row(("action", &[]), Yes, TEXT, Some(MandateLabel::Action)),
        row(
            ("conditions", &[]),
            No,
            MARKDOWN,
            Some(MandateLabel::Conditions),
        ),
        row(
            ("max_amount", &[]),
            No,
            AMOUNT,
            Some(MandateLabel::MaxAmount),
        ),
        row(("max_count", &[]), No, TEXT, Some(MandateLabel::MaxCount)),
        row(("period", &[]), No, TEXT, Some(MandateLabel::Period)),
        row(("valid_from", &[]), No, DATE, Some(MandateLabel::ValidFrom)),
        row(
            ("valid_until", &[]),
            Yes,
            DATE,
            Some(MandateLabel::ValidUntil),
        ),
        row(("payment_payload", &["transaction_id"]), No, TEXT, None),
        row(
            ("payment_payload", &["amount"]),
            No,
            AMOUNT,
            Some(MandateLabel::Amount),
        ),
        row(
            ("payment_payload", &["payee", "name"]),
            No,
            TEXT,
            Some(MandateLabel::Payee),
        ),
        row(("payment_payload", &["payee", "id"]), No, TEXT, None),
        row(
            ("payment_payload", &["payee", "logo"]),
            No,
            IMAGE,
            Some(MandateLabel::PayeeLogo),
        ),
        row(
            ("payment_payload", &["payee", "logo#integrity"]),
            No,
            TEXT,
            None,
        ),
    ]
};

/// A display array of a text of the wallet's own: its default entry, which every language
/// matches, as the crate modules cover every language of the wallet.
fn own(text: MandateLabel) -> DisplayArray<'static> {
    DisplayArray::built(vec![Localized {
        locale: EntryLocale::Default,
        label: LabelForm::Own(text),
    }])
}

/// The metadata a Mandate type renders with: the rulebook's claims and labels, and the
/// `security_hint` of the credential's metadata for the type. Its title and confirm action are the
/// subtype's and its denial the wallet's, as for a type whose metadata names none.
pub(crate) fn metadata<'m>(
    given: &'m Node<'m>,
    limits: LabelLimits,
) -> Result<Metadata<'m>, Unsupported> {
    let claims = TABLE
        .iter()
        .map(|row| ClaimMeta {
            path: ClaimPath::of(
                Step::Key(Cow::Borrowed(row.first)),
                row.below.iter().map(|key| Step::Key(Cow::Borrowed(*key))),
            ),
            mandatory: row.mandatory,
            display: row.label.map(|label| Displayed {
                names: own(label),
                value: row.value,
            }),
        })
        .collect();
    let mut ui = Vec::new();
    if let Some(hint) = hint(given)? {
        ui.push(UiLabel::parse(UiKey::SecurityHint, hint, limits)?);
    }
    Ok(Metadata { claims, ui })
}

/// The `security_hint` entries of the metadata the credential gives for the type, an object.
fn hint<'m>(given: &'m Node<'m>) -> Result<Option<&'m Node<'m>>, Unsupported> {
    let object = given.as_object().ok_or(Unsupported::NoClaims)?;
    match object.get("ui_labels") {
        None => Ok(None),
        Some(Node::Object(labels)) => Ok(labels.get("security_hint")),
        Some(_) => Err(Unsupported::UiLabelsNotObject),
    }
}
