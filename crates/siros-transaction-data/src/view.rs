//! What the consent screen shows for one transaction: the generic rendering of PaSO View, Section
//! 2, for every type and every source.

use siros_oid4vp::RequestSignature;

use crate::definition::{BaseType, LabelFormat, LabelText, Prominence, SecurityHint};
use crate::image::{Image, ImageFault};
use crate::payload::{Location, Scalar};
use crate::sources::{Rulebook, SourceKind};
use crate::type_id::TypeId;

/// The display of one transaction data entry: its UI elements and a row per displayed claim
/// instance, in the order of the definition's claims.
///
/// The core checks each label against its role's limit with each value as the payload writes
/// it, since the UI formats the values. The UI checks each label again once formatted, with
/// [`LabelText::parse`] under [`LabelLength::Final`](crate::LabelLength::Final) and the rules of
/// [`TransactionView::source`], and treats a label over its limit as an entry that is not
/// compatible (PaSO View, Section 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionView {
    pub(crate) type_id: TypeId,
    pub(crate) source: SourceKind,
    pub(crate) rulebook: Rulebook,
    pub(crate) title: Option<ShownLabel>,
    pub(crate) affirmative: Option<ShownLabel>,
    pub(crate) denial: Option<ShownLabel>,
    pub(crate) security_hint: Option<LabelText<SecurityHint>>,
    pub(crate) rows: Vec<Row>,
    pub(crate) absent: Vec<(Location, ImageFault)>,
    pub(crate) signature: RequestSignature,
}

/// A piece of a shown text: the metadata's own text, or a payload value the UI formats by its
/// type (PaSO View, Section 3, `template:`, step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    /// Text of the label or the template.
    Text(String),
    /// A value a placeholder resolved to.
    Value(Scalar),
}

/// A label as shown: its segments, one text unless it was a template, and how the whole is
/// formatted. The core's length check counts each value as the payload writes it; the UI checks
/// the formatted label again ([`TransactionView`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShownLabel {
    pub(crate) segments: Vec<Segment>,
    pub(crate) format: LabelFormat,
}

/// The value of a `template:` claim: the interpolated segments, and the inner type that formats
/// the whole. The text of the segments, each value as the payload writes it, is a value of the
/// inner type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interpolated {
    pub(crate) segments: Vec<Segment>,
    pub(crate) inner: BaseType,
}

/// A displayed claim instance: its location in the payload, its label, its value, and the
/// prominence TS12 type metadata gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub(crate) location: Location,
    pub(crate) label: ShownLabel,
    pub(crate) value: RowValue,
    pub(crate) prominence: Option<Prominence>,
}

/// The value of a row, typed for the UI to format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowValue {
    /// `label_only`: the label is shown alone.
    LabelOnly,
    /// A value formatted by its type.
    Value(Scalar),
    /// A `template:` value.
    Template(Interpolated),
    /// An image, as information for the UI ([`Image`]).
    Image(Image),
}

/// Whether the UI warns that the request arrived unsigned, and requires explicit confirmation
/// before it continues (EC TS12 v1.0.1, Section 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnsignedWarning {
    /// The request is unsigned and the type's rulebook is TS12's: warn and confirm.
    Required,
    /// The request arrived signed, or the rulebook is no TS12 one.
    NotNeeded,
}

impl TransactionView {
    /// The `type` value.
    #[must_use]
    pub fn type_id(&self) -> &TypeId {
        &self.type_id
    }

    /// The source of the definition the view renders.
    #[must_use]
    pub fn source(&self) -> SourceKind {
        self.source
    }

    /// The rulebook of the payload.
    #[must_use]
    pub fn rulebook(&self) -> Rulebook {
        self.rulebook
    }

    /// `transaction_title`. `None`: the wallet may title the screen itself.
    #[must_use]
    pub fn transaction_title(&self) -> Option<&ShownLabel> {
        self.title.as_ref()
    }

    /// `affirmative_action_label`. `None`: the wallet labels the control that confirms.
    #[must_use]
    pub fn affirmative_action_label(&self) -> Option<&ShownLabel> {
        self.affirmative.as_ref()
    }

    /// `denial_action_label`. `None`: the wallet labels the control that cancels.
    #[must_use]
    pub fn denial_action_label(&self) -> Option<&ShownLabel> {
        self.denial.as_ref()
    }

    /// `security_hint`, shown exactly as given (PaSO View, Section 2).
    #[must_use]
    pub fn security_hint(&self) -> Option<&LabelText<SecurityHint>> {
        self.security_hint.as_ref()
    }

    /// The rows, in the order of the definition's claims, wildcards expanded (PaSO View,
    /// Section 2).
    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// The images of a TS12 payload that are not admitted, each with why: the view leaves them
    /// out (PaSO Proof SD-JWT-VC and SVG, Section 2).
    #[must_use]
    pub fn absent_images(&self) -> &[(Location, ImageFault)] {
        &self.absent
    }

    /// Whether the UI warns that the request arrived unsigned (EC TS12 v1.0.1, Section 3.1).
    #[must_use]
    pub fn unsigned_warning(&self) -> UnsignedWarning {
        match (self.signature, self.rulebook) {
            (RequestSignature::Unsigned, Rulebook::Ts12(_)) => UnsignedWarning::Required,
            (RequestSignature::Signed, _) | (RequestSignature::Unsigned, Rulebook::Generic) => {
                UnsignedWarning::NotNeeded
            }
        }
    }
}

impl ShownLabel {
    /// The segments, in order.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// How the whole is formatted: plain or `mini_markdown`.
    #[must_use]
    pub fn format(&self) -> LabelFormat {
        self.format
    }
}

impl Interpolated {
    /// The segments, in order.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// The inner type, which formats the whole.
    #[must_use]
    pub fn inner(&self) -> BaseType {
        self.inner
    }
}

impl Row {
    /// The claim instance's location in the payload.
    #[must_use]
    pub fn location(&self) -> &Location {
        &self.location
    }

    /// The label.
    #[must_use]
    pub fn label(&self) -> &ShownLabel {
        &self.label
    }

    /// The value.
    #[must_use]
    pub fn value(&self) -> &RowValue {
        &self.value
    }

    /// The prominence TS12 type metadata gives the row (EC TS12 v1.0.1, Section 3.3.1).
    #[must_use]
    pub fn prominence(&self) -> Option<Prominence> {
        self.prominence
    }
}
