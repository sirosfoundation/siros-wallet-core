//! What keeps one `transaction_data` entry from rendering for one credential, each rule with the
//! clause that decides it. First match (Core §7.4.2) gives way to the next entry on
//! [`Unsupported`] and [`NotCompatible`]; [`Excluded`] excludes the credential.

use crate::value::BadValue;
use siros_explain::Explain;
use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::plugins::Clause;
use siros_openid4vp::refusal::{QuotedList, ReprItem, ReprOption};

use crate::adhoc::AdhocFailure;
use crate::conform::ClaimIndex;
use crate::image::ImageFailure;
use crate::labels::{Directional, LabelViolation};
use crate::metadata::{ArrayAt, UiKey};
use crate::path::Mismatch;
use crate::phase2::OptionalModule;
use crate::render::ItemBound;
use crate::rulebook::PasoType;

/// Why an entry does not render for a credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "paso.outcome")]
pub enum Outcome {
    /// The credential does not support the entry's type.
    #[error(transparent)]
    Unsupported(#[from] Unsupported),
    /// The entry is not compatible with the credential.
    #[error(transparent)]
    NotCompatible(#[from] NotCompatible),
    /// No locale of the wallet's list completes the display.
    #[error(transparent)]
    Excluded(#[from] Excluded),
}

impl Outcome {
    /// The clause that decides it.
    #[must_use]
    pub fn clause(&self) -> Clause {
        match self {
            Self::Unsupported(rule) => rule.clause(),
            Self::NotCompatible(rule) => rule.clause(),
            Self::Excluded(rule) => rule.clause(),
        }
    }
}

/// The credential does not support the entry's type (Proof Metadata §3.3, last sentence; Core
/// §7.4.2 step 2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "paso.unsupported")]
pub enum Unsupported {
    /// The credential holds no PaSO document.
    #[error("the credential has no PaSO metadata")]
    NoPasoMetadata,
    /// The signed credential metadata lists no entry for the type.
    #[error("the credential's metadata does not list {0}")]
    NotListed(#[explain(name = "kind")] PasoType<'static>),
    /// The type's entry is `null`.
    #[error("no transaction_data_types entry for {0}")]
    NoEntry(#[explain(name = "kind")] PasoType<'static>),
    /// The entry is no object with a `claims` array.
    #[error("no claims array")]
    NoClaims,
    /// More than 100 claims.
    #[error("{0} claims, more than 100")]
    TooManyClaims(#[explain(name = "claims")] usize),
    /// A claim that is no object with a claims path pointer.
    #[error("claim {0}: no valid path")]
    InvalidPath(#[explain(name = "claim")] ClaimIndex),
    /// Two claims with one path.
    #[error("two claims with path {0}")]
    PathTwice(#[explain(name = "path")] ReprItem),
    /// A `value_type` on a claim without `display`.
    #[error("claim {0}: value_type without display")]
    ValueTypeWithoutDisplay(#[explain(name = "claim")] ReprItem),
    /// A display array that is no non-empty array.
    #[error("{}: not a non-empty array", .0.logged())]
    EmptyArray(#[explain(name = "at")] ArrayAt),
    /// A display entry without its text as a string.
    #[error("{}: an entry without a string {}", .0.logged(), .1)]
    EntryWithoutText(
        #[explain(name = "at")] ArrayAt,
        #[explain(name = "member")] &'static str,
    ),
    /// A label typed other than `mini_markdown` or `template:mini_markdown`, or a typed
    /// `security_hint`.
    #[error("{}: {member} {written}", .at.logged())]
    LabelType {
        /// The array.
        at: ArrayAt,
        /// `display_type` or `value_type`.
        member: &'static str,
        /// The type.
        written: ReprItem,
    },
    /// An explicit `null` locale.
    #[error("{}: locale null", .0.logged())]
    NullLocale(#[explain(name = "at")] ArrayAt),
    /// A locale that is no string, or one given twice.
    #[error("{}: locale {} repeated or not a tag", .0.logged(), .1)]
    LocaleRepeated(
        #[explain(name = "at")] ArrayAt,
        #[explain(name = "locale")] ReprItem,
    ),
    /// Two entries without a locale.
    #[error("{}: more than one entry without a locale", .0.logged())]
    DefaultTwice(#[explain(name = "at")] ArrayAt),
    /// A claim label that breaks §3.3 as written.
    #[error("claim {0} label: {1}")]
    ClaimLabel(
        #[explain(name = "claim")] ReprItem,
        #[explain(name = "violation")] LabelViolation,
    ),
    /// A `label_only` claim that is `mandatory` (View §3 `label_only`).
    #[error("claim {0}: label_only and mandatory")]
    MandatoryLabelOnly(#[explain(name = "claim")] ReprItem),
    /// `ui_labels` that is no object.
    #[error("ui_labels is not an object")]
    UiLabelsNotObject,
    /// A UI label that breaks §3.3 as written.
    #[error("ui_labels.{0}: {1}")]
    UiLabel(
        #[explain(name = "key")] UiKey,
        #[explain(name = "violation")] LabelViolation,
    ),
    /// A type under the Generic prefix that is no Generic type identifier.
    #[error("{0} is not a Generic type identifier")]
    NotGeneric(#[explain(name = "kind")] PasoType<'static>),
    /// A type under the Mandate prefix that is no Mandate type identifier.
    #[error("{0} is not a Mandate type identifier")]
    NotMandate(#[explain(name = "kind")] PasoType<'static>),
}

impl Unsupported {
    /// The clause that decides it.
    #[must_use]
    pub const fn clause(&self) -> Clause {
        Clause::cited(match self {
            Self::NoPasoMetadata | Self::NotListed(_) => "Core §7.4.2 step 2",
            Self::NoEntry(_) | Self::NoClaims => "Proof Metadata §3",
            Self::TooManyClaims(_)
            | Self::PathTwice(_)
            | Self::LocaleRepeated(..)
            | Self::DefaultTwice(_)
            | Self::ClaimLabel(..)
            | Self::UiLabel(..) => "Proof Metadata §3.3",
            Self::InvalidPath(_) => "Proof Metadata §3.1; OpenID4VCI B.2",
            Self::ValueTypeWithoutDisplay(_) => "View §3; Proof Metadata §3.1",
            Self::EmptyArray(_) => "Proof Metadata §3.1",
            Self::EntryWithoutText(..) => "Proof Metadata §3.1-3.2",
            Self::LabelType { .. } => "Proof Metadata §3.3; View §3",
            Self::NullLocale(_) | Self::UiLabelsNotObject => "Proof Metadata §3.2",
            Self::MandatoryLabelOnly(_) => "View §3 label_only",
            Self::NotGeneric(_) => "Generic §1",
            Self::NotMandate(_) => "Mandate §1",
        })
    }
}

/// The entry is not compatible with the credential: first match tries the next entry (Core
/// §7.4.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "paso.not_compatible")]
pub enum NotCompatible {
    /// A displayed claim declares a value type the wallet does not support (View §3).
    #[error("claim {path}: value_type {written}")]
    ValueType {
        /// The claim's path.
        path: ReprItem,
        /// The value type.
        written: ReprOption,
    },
    /// The entry's payload is no object (Core §7.1).
    #[error("payload is not an object")]
    PayloadNotObject,
    /// A path reads an element of another kind.
    #[error(transparent)]
    Mismatch(#[from] Mismatch),
    /// A value that does not conform to its value type (View §3).
    #[error("{value_type} {bad}")]
    Value {
        /// The value type, or `plain text`.
        value_type: &'static str,
        /// What the value lacks.
        bad: BadValue,
    },
    /// An image value that is no string (View §3).
    #[error("image value {0}: not a string")]
    ImageNotString(#[explain(name = "path")] ReprItem),
    /// An image that fails a rule, or whose resolution failed (View §3 `image`; Core §7.4.2
    /// step 3).
    #[error("image {url}: {failure}")]
    Image {
        /// The first 60 characters of the URL, in ASCII once it parses as an https URL.
        url: String,
        /// The rule.
        failure: ImageFailure,
    },
    /// A payload string with a directional embedding, override or open isolate (Proof
    /// Metadata §3.3).
    #[error("payload {path}: {violation}")]
    PayloadDirectional {
        /// The string's path.
        path: ReprItem,
        /// The violation.
        violation: Directional,
    },
    /// A payload field no claim path covers.
    #[error("payload field {0} is not covered by a claim path")]
    Uncovered(#[explain(name = "field")] ReprItem),
    /// A mandatory claim the payload lacks.
    #[error("mandatory claim {0} is absent")]
    MandatoryAbsent(#[explain(name = "claim")] ReprItem),
    /// A template value that is no string (View §3 template).
    #[error("claim {0}: a template value is not a string")]
    TemplateNotString(#[explain(name = "claim")] ReprItem),
    /// A placeholder naming an `image`, `label_only` or template claim (View §3 template).
    #[error("placeholder {{{placeholder}}} references a {value_type} claim")]
    ForbiddenReference {
        /// The claim the placeholder names.
        placeholder: ClaimIndex,
        /// The referenced claim's value type.
        value_type: String,
    },
    /// A placeholder naming a claim with more `null`s than the referencing claim (View §3
    /// template).
    #[error("placeholder {{{0}}} has more nulls than its referencing claim")]
    MoreNulls(#[explain(name = "placeholder")] ClaimIndex),
    /// A placeholder naming a claim without `value_type` whose value is no string (View §3
    /// template).
    #[error("placeholder {{{0}}}: a value without value_type is not a string")]
    ReferenceNotString(#[explain(name = "placeholder")] ClaimIndex),
    /// Every locale lost an entry to a template's absent claim (View §3 template).
    #[error("every locale lost an entry to a template's absent claim")]
    TemplatesExhausted,
    /// A label that breaks §3.3 once rendered (View §2).
    #[error("{at}: {violation}")]
    RenderedLabel {
        /// Which label.
        at: RenderedAt,
        /// The violation.
        violation: LabelViolation,
    },
    /// More rendered items than the wallet's bound (View §2).
    #[error("{items} rendered items, over the bound {bound}")]
    TooManyItems {
        /// The rows and UI elements.
        items: usize,
        /// The bound.
        bound: ItemBound,
    },
    /// A field the Payment rulebook requires is absent (Payment §1).
    #[error("required {0} absent")]
    PaymentRequired(#[explain(name = "member")] ReprItem),
    /// A Generic payload of more than 11 properties (Generic §3).
    #[error("more than 11 payload properties")]
    GenericProperties,
    /// A Generic payload without a non-empty string `transaction_id` (Generic §3).
    #[error("transaction_id absent")]
    GenericTransactionId,
    /// A Generic custom claim that is neither a string nor `null` (Generic §3.1).
    #[error("custom claim {0}: not a string or null")]
    GenericCustom(#[explain(name = "claim")] String),
    /// A Generic embedded payment payload without a field the Payment rulebook requires
    /// (Generic §3.2).
    #[error("payment_payload {0} absent")]
    GenericPayment(#[explain(name = "member")] ReprItem),
    /// A Mandate embedded payment payload without a field the Payment rulebook requires
    /// (Mandate §2.2).
    #[error("payment_payload {0} absent")]
    MandatePayment(#[explain(name = "member")] ReprItem),
    /// `risk_signal_profiles` that is no array of profile identifiers (Risk Signals §3.2).
    #[error("risk_signal_profiles is not an array of profile identifiers")]
    RiskProfiles,
    /// A risk signal profile the wallet does not hold (Risk Signals §4.1).
    #[error("the wallet holds no risk signal profile {0}")]
    UnknownRiskProfile(#[explain(name = "profile")] String),
    /// `risk_signals` that is no array (Risk Signals §4.1).
    #[error("risk_signals is not an array")]
    RiskSignalsNotArray,
    /// A malformed `risk_signals` entry (Risk Signals §3.4, §4.1).
    #[error("risk_signals entry {0} is malformed")]
    RiskSignalMalformed(#[explain(name = "signal")] ReprItem),
    /// `encrypted` that is no boolean (Risk Signals §7.2).
    #[error("encrypted is not a boolean")]
    EncryptedNotBoolean,
    /// The risk signals must be encrypted and the issuer publishes no key the wallet can use
    /// (Risk Signals §7.3).
    #[error(
        "its risk signals must be encrypted and the issuer publishes no key the wallet can use"
    )]
    NoEncryptionKey,
    /// The response needs a module phase 2 found the build lacks: an mdoc's encrypted risk
    /// signals need `COSE_Encrypt` (Risk Signals §7.6).
    #[error("its response needs the {0} module, which the build lacks")]
    Lacks(#[explain(name = "module")] OptionalModule),
    /// The ad-hoc metadata JWT fails a check (Proof Metadata §5.3).
    #[error("ad-hoc metadata: {0}")]
    Adhoc(
        #[from]
        #[explain(name = "failure")]
        AdhocFailure,
    ),
}

impl NotCompatible {
    /// The clause that decides it.
    #[must_use]
    pub const fn clause(&self) -> Clause {
        Clause::cited(match self {
            Self::ValueType { .. } | Self::Value { .. } | Self::ImageNotString(_) => "View §3",
            Self::PayloadNotObject => "Core §7.1",
            Self::Mismatch(_) | Self::Uncovered(_) | Self::MandatoryAbsent(_) => {
                "Core §7.4.2 step 2"
            }
            Self::Image { .. } => "View §3 image; Core §7.4.2 step 3",
            Self::PayloadDirectional { .. } => "Proof Metadata §3.3",
            Self::TemplateNotString(_)
            | Self::ForbiddenReference { .. }
            | Self::MoreNulls(_)
            | Self::ReferenceNotString(_)
            | Self::TemplatesExhausted => "View §3 template",
            Self::RenderedLabel { .. } => "View §2; Proof Metadata §3.3",
            Self::TooManyItems { .. } => "View §2",
            Self::PaymentRequired(_) => "Payment §1; Core §7.4.2 step 2",
            Self::GenericProperties | Self::GenericTransactionId => "Generic §3",
            Self::GenericCustom(_) => "Generic §3.1",
            Self::GenericPayment(_) => "Generic §3.2; Payment §1",
            Self::MandatePayment(_) => "Mandate §2.2; Payment §1",
            Self::RiskProfiles => "Risk Signals §3.2",
            Self::UnknownRiskProfile(_) | Self::RiskSignalsNotArray => "Risk Signals §4.1",
            Self::RiskSignalMalformed(_) => "Risk Signals §3.4; §4.1",
            Self::EncryptedNotBoolean => "Risk Signals §7.2",
            Self::NoEncryptionKey => "Risk Signals §7.3",
            Self::Lacks(_) => "Risk Signals §7.6",
            Self::Adhoc(_) => "Proof Metadata §5.3",
        })
    }
}

/// Which rendered label breaks §3.3.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "paso.rendered_at")]
pub enum RenderedAt {
    /// A claim's label at a payload path.
    #[error("claim {0} label")]
    Claim(#[explain(name = "claim")] ReprItem),
    /// A UI label.
    #[error("ui_labels.{0}")]
    Ui(#[explain(name = "key")] UiKey),
}

/// No locale of the wallet's list completes every display array: the credential is excluded
/// (View §4).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "paso")]
#[error("no locale of {} matches every display array", quoted(.locales))]
pub struct Excluded {
    /// The wallet's locale priority list.
    #[explain(skip)]
    pub(crate) locales: Vec<LocaleTag>,
}

/// The tags as Python's `repr` of their list writes it.
fn quoted(locales: &[LocaleTag]) -> String {
    let tags: Vec<&str> = locales.iter().map(LocaleTag::as_str).collect();
    QuotedList(&tags).to_string()
}

impl Excluded {
    /// The clause that decides it.
    #[must_use]
    pub const fn clause(&self) -> Clause {
        Clause::cited("View §4")
    }
}
