//! The Mandate rulebook's metadata (Mandate §2): a wallet implementing it ships with every
//! claim, its position and its rendering, and labels them with its own texts. The credential's
//! metadata contributes its `security_hint`, shown exactly.

use std::borrow::Cow;

use siros_explain::Explain;
use siros_explain::Text;
use siros_openid4vp::claims::{ClaimPath, Step};
use siros_openid4vp::json::Node;
use siros_openid4vp::rows::{FormattedKind, ValueKind, WalletText};

use crate::metadata::{
    ClaimMeta, DisplayArray, Displayed, EntryLocale, LabelForm, Localized, Mandatory, Metadata,
    UiKey, UiLabel, ValueType,
};
use crate::outcome::Unsupported;
use crate::rulebook::{Confirm, Rulebook, Subtype, Title};

/// A label of the Mandate claims, by the screens of the rulebook's examples: a message of the
/// crate's module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[explain(domain = "paso.mandate")]
pub enum MandateLabel {
    /// `mandate_id`.
    #[error("Mandate reference")]
    MandateId,
    /// `mandatee.name` and `mandatee.logo`, which draws under it (Mandate A.2).
    #[error("Authorized party")]
    Mandatee,
    /// `action`.
    #[error("Authorized action")]
    Action,
    /// `conditions`.
    #[error("Conditions")]
    Conditions,
    /// `max_amount`.
    #[error("Maximum amount per use")]
    MaxAmount,
    /// `max_count`.
    #[error("Maximum uses")]
    MaxCount,
    /// `period`.
    #[error("Per period")]
    Period,
    /// `valid_from`.
    #[error("Valid from")]
    ValidFrom,
    /// `valid_until`.
    #[error("Valid until")]
    ValidUntil,
    /// `payment_payload.amount`, as Payment A.1's metadata labels it.
    #[error("Amount")]
    Amount,
    /// `payment_payload.payee.name`, as Payment A.1's metadata labels it.
    #[error("Payee")]
    Payee,
    /// `payment_payload.payee.logo`, as Payment A.1's metadata labels it.
    #[error("Payee logo")]
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

/// A text of the wallet's own a rulebook's metadata labels with: a message of a crate module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnText {
    /// A Mandate claim's label.
    Label(MandateLabel),
    /// The transaction title.
    Title(Title),
    /// The confirm action.
    Confirm(Confirm),
    /// The wallet's denial action.
    Deny,
}

impl OwnText {
    /// The text.
    #[must_use]
    pub fn text(self) -> Text {
        match self {
            Self::Label(label) => Text::of(&label),
            Self::Title(title) => Text::of(&title),
            Self::Confirm(confirm) => Text::of(&confirm),
            Self::Deny => Text::of(&WalletText::Deny),
        }
    }
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
fn own(text: OwnText) -> DisplayArray<'static> {
    DisplayArray::built(vec![Localized {
        locale: EntryLocale::Default,
        label: LabelForm::Own(text),
    }])
}

/// The metadata a Mandate type renders with: the rulebook's claims and labels, its title and
/// confirm action for the subtype, the wallet's denial, and the `security_hint` of the
/// credential's metadata for the type.
pub(crate) fn metadata<'m>(
    subtype: Subtype<'_>,
    given: &'m Node<'m>,
) -> Result<Metadata<'m>, Unsupported> {
    let rulebook = Rulebook::Mandate(subtype);
    let claims = TABLE
        .iter()
        .map(|row| ClaimMeta {
            path: ClaimPath::of(
                Step::Key(Cow::Borrowed(row.first)),
                row.below.iter().map(|key| Step::Key(Cow::Borrowed(*key))),
            ),
            mandatory: row.mandatory,
            display: row.label.map(|label| Displayed {
                names: own(OwnText::Label(label)),
                value: row.value,
            }),
        })
        .collect();
    let mut ui = vec![
        UiLabel {
            key: UiKey::TransactionTitle,
            entries: own(OwnText::Title(rulebook.title())),
        },
        UiLabel {
            key: UiKey::AffirmativeActionLabel,
            entries: own(OwnText::Confirm(rulebook.confirm())),
        },
        UiLabel {
            key: UiKey::DenialActionLabel,
            entries: own(OwnText::Deny),
        },
    ];
    if let Some(hint) = hint(given)? {
        ui.push(UiLabel::parse(UiKey::SecurityHint, hint)?);
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
