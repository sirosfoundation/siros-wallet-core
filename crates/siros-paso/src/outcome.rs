//! What keeps one `transaction_data` entry from rendering for one credential, each rule with the
//! clause that decides it. First match (Core §7.4.2) gives way to the next entry on
//! [`Unsupported`] and [`NotCompatible`]; [`Excluded`] excludes the credential.

use std::fmt;

use siros_explain::Explain;
use siros_i18n::Message;
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
use crate::value::BadValue;

/// Why an entry does not render for a credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
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
pub enum Unsupported {
    /// The credential holds no PaSO document.
    #[error("the credential has no PaSO metadata")]
    #[explain(id = "unsupported.no_paso_metadata")]
    NoPasoMetadata,
    /// The signed credential metadata lists no entry for the type.
    #[error("the credential's metadata does not list {kind}")]
    #[explain(id = "unsupported.not_listed")]
    NotListed {
        /// The transaction type.
        kind: PasoType<'static>,
    },
    /// The type's entry is `null`.
    #[error("no transaction_data_types entry for {kind}")]
    #[explain(id = "unsupported.no_entry")]
    NoEntry {
        /// The transaction type.
        kind: PasoType<'static>,
    },
    /// The entry is no object with a `claims` array.
    #[error("no claims array")]
    #[explain(id = "unsupported.no_claims")]
    NoClaims,
    /// More than 100 claims.
    #[error("{claims} claims, more than 100")]
    #[explain(id = "unsupported.too_many_claims")]
    TooManyClaims {
        /// The number of claims.
        claims: usize,
    },
    /// A claim that is no object with a claims path pointer.
    #[error("claim {claim}: no valid path")]
    #[explain(id = "unsupported.invalid_path")]
    InvalidPath {
        /// The claim's index in `claims`.
        claim: ClaimIndex,
    },
    /// Two claims with one path.
    #[error("two claims with path {}", .path.repr_text())]
    #[explain(id = "unsupported.path_twice")]
    PathTwice {
        /// The path as written.
        path: ReprItem,
    },
    /// A `value_type` on a claim without `display`.
    #[error("claim {}: value_type without display", .claim.repr_text())]
    #[explain(id = "unsupported.value_type_without_display")]
    ValueTypeWithoutDisplay {
        /// The claim's path.
        claim: ReprItem,
    },
    /// A display array that is no non-empty array.
    #[error("{at}: not a non-empty array")]
    #[explain(id = "unsupported.empty_array")]
    EmptyArray {
        /// The array.
        at: ArrayAt,
    },
    /// A display entry without its text as a string.
    #[error("{at}: an entry without a string {member}")]
    #[explain(id = "unsupported.entry_without_text")]
    EntryWithoutText {
        /// The array.
        at: ArrayAt,
        /// The member that holds the text.
        member: &'static str,
    },
    /// A label typed other than `mini_markdown` or `template:mini_markdown`, or a typed
    /// `security_hint`.
    #[error("{at}: {member} {}", .written.repr_text())]
    #[explain(id = "unsupported.label_type")]
    LabelType {
        /// The array.
        at: ArrayAt,
        /// `display_type` or `value_type`.
        member: &'static str,
        /// The type.
        written: ReprItem,
    },
    /// An explicit `null` locale.
    #[error("{at}: locale null")]
    #[explain(id = "unsupported.null_locale")]
    NullLocale {
        /// The array.
        at: ArrayAt,
    },
    /// A locale that is no string, or one given twice.
    #[error("{at}: locale {} repeated or not a tag", .locale.repr_text())]
    #[explain(id = "unsupported.locale_repeated")]
    LocaleRepeated {
        /// The array.
        at: ArrayAt,
        /// The locale as written.
        locale: ReprItem,
    },
    /// Two entries without a locale.
    #[error("{at}: more than one entry without a locale")]
    #[explain(id = "unsupported.default_twice")]
    DefaultTwice {
        /// The array.
        at: ArrayAt,
    },
    /// A claim label that breaks §3.3 as written.
    #[error("claim {} label: {violation}", .claim.repr_text())]
    #[explain(id = "unsupported.claim_label")]
    ClaimLabel {
        /// The claim's path.
        claim: ReprItem,
        /// The rule the label breaks.
        #[source]
        violation: LabelViolation,
    },
    /// A `label_only` claim that is `mandatory` (View §3 `label_only`).
    #[error("claim {}: label_only and mandatory", .claim.repr_text())]
    #[explain(id = "unsupported.mandatory_label_only")]
    MandatoryLabelOnly {
        /// The claim's path.
        claim: ReprItem,
    },
    /// `ui_labels` that is no object.
    #[error("ui_labels is not an object")]
    #[explain(id = "unsupported.ui_labels_not_object")]
    UiLabelsNotObject,
    /// A UI label that breaks §3.3 as written.
    #[error("ui_labels.{key}: {violation}")]
    #[explain(id = "unsupported.ui_label")]
    UiLabel {
        /// The UI label.
        key: UiKey,
        /// The rule the label breaks.
        #[source]
        violation: LabelViolation,
    },
    /// A type under the Generic prefix that is no Generic type identifier.
    #[error("{kind} is not a Generic type identifier")]
    #[explain(id = "unsupported.not_generic")]
    NotGeneric {
        /// The transaction type.
        kind: PasoType<'static>,
    },
    /// A type under the Mandate prefix that is no Mandate type identifier.
    #[error("{kind} is not a Mandate type identifier")]
    #[explain(id = "unsupported.not_mandate")]
    NotMandate {
        /// The transaction type.
        kind: PasoType<'static>,
    },
    /// A template label holding U+FDD0, the character its conversion reads its placeholders as,
    /// or U+0000, which no MessageFormat 2 text holds.
    #[error("{at}: a template holds U+FDD0 or U+0000")]
    #[explain(id = "unsupported.reserved")]
    Reserved {
        /// The array.
        at: ArrayAt,
    },
}

impl Unsupported {
    /// The clause that decides it.
    #[must_use]
    pub const fn clause(&self) -> Clause {
        Clause::cited(match self {
            Self::NoPasoMetadata | Self::NotListed { .. } => "Core §7.4.2 step 2",
            Self::NoEntry { .. } | Self::NoClaims => "Proof Metadata §3",
            Self::TooManyClaims { .. }
            | Self::PathTwice { .. }
            | Self::LocaleRepeated { .. }
            | Self::DefaultTwice { .. }
            | Self::ClaimLabel { .. }
            | Self::UiLabel { .. } => "Proof Metadata §3.3",
            Self::InvalidPath { .. } => "Proof Metadata §3.1; OpenID4VCI B.2",
            Self::ValueTypeWithoutDisplay { .. } => "View §3; Proof Metadata §3.1",
            Self::EmptyArray { .. } => "Proof Metadata §3.1",
            Self::EntryWithoutText { .. } => "Proof Metadata §3.1-3.2",
            Self::LabelType { .. } => "Proof Metadata §3.3; View §3",
            Self::NullLocale { .. } | Self::UiLabelsNotObject => "Proof Metadata §3.2",
            Self::MandatoryLabelOnly { .. } => "View §3 label_only",
            Self::Reserved { .. } => "View §3 template",
            Self::NotGeneric { .. } => "Generic §1",
            Self::NotMandate { .. } => "Mandate §1",
        })
    }
}

/// The entry is not compatible with the credential: first match tries the next entry (Core
/// §7.4.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum NotCompatible {
    /// A displayed claim declares a value type the wallet does not support (View §3).
    #[error("claim {}: value_type {}", .path.repr_text(), .written.repr_text())]
    #[explain(id = "not_compatible.value_type")]
    ValueType {
        /// The claim's path.
        path: ReprItem,
        /// The value type.
        written: ReprOption,
    },
    /// The entry's payload is no object (Core §7.1).
    #[error("payload is not an object")]
    #[explain(id = "not_compatible.payload_not_object")]
    PayloadNotObject,
    /// A path reads an element of another kind.
    #[error(transparent)]
    Mismatch(#[from] Mismatch),
    /// A value that does not conform to its value type (View §3).
    #[error("{value_type} {bad}")]
    #[explain(id = "not_compatible.value")]
    Value {
        /// The value type, or `plain text`.
        value_type: &'static str,
        /// What the value lacks.
        #[source]
        bad: BadValue,
    },
    /// An image value that is no string (View §3).
    #[error("image value {}: not a string", .path.repr_text())]
    #[explain(id = "not_compatible.image_not_string")]
    ImageNotString {
        /// The value's path.
        path: ReprItem,
    },
    /// An image that fails a rule, or whose resolution failed (View §3 `image`; Core §7.4.2
    /// step 3).
    #[error("image {url}: {failure}")]
    #[explain(id = "not_compatible.image")]
    Image {
        /// The first 60 characters of the URL, in ASCII once it parses as an https URL.
        url: String,
        /// The rule.
        #[source]
        failure: ImageFailure,
    },
    /// A payload string with a directional embedding, override or open isolate (Proof
    /// Metadata §3.3).
    #[error("payload {}: {violation}", .path.repr_text())]
    #[explain(id = "not_compatible.payload_directional")]
    PayloadDirectional {
        /// The string's path.
        path: ReprItem,
        /// The violation.
        #[source]
        violation: Directional,
    },
    /// A payload field no claim path covers.
    #[error("payload field {} is not covered by a claim path", .field.repr_text())]
    #[explain(id = "not_compatible.uncovered")]
    Uncovered {
        /// The field's path.
        field: ReprItem,
    },
    /// A mandatory claim the payload lacks.
    #[error("mandatory claim {} is absent", .claim.repr_text())]
    #[explain(id = "not_compatible.mandatory_absent")]
    MandatoryAbsent {
        /// The claim's path.
        claim: ReprItem,
    },
    /// A template value that is no string (View §3 template).
    #[error("claim {}: a template value is not a string", .claim.repr_text())]
    #[explain(id = "not_compatible.template_not_string")]
    TemplateNotString {
        /// The claim's path.
        claim: ReprItem,
    },
    /// A placeholder naming an `image`, `label_only` or template claim (View §3 template).
    #[error("placeholder {{{placeholder}}} references a {value_type} claim")]
    #[explain(id = "not_compatible.forbidden_reference")]
    ForbiddenReference {
        /// The claim the placeholder names.
        placeholder: ClaimIndex,
        /// The referenced claim's value type.
        value_type: String,
    },
    /// A placeholder naming a claim with more `null`s than the referencing claim (View §3
    /// template).
    #[error("placeholder {{{placeholder}}} has more nulls than its referencing claim")]
    #[explain(id = "not_compatible.more_nulls")]
    MoreNulls {
        /// The claim the placeholder names.
        placeholder: ClaimIndex,
    },
    /// A placeholder naming a claim without `value_type` whose value is no string (View §3
    /// template).
    #[error("placeholder {{{placeholder}}}: a value without value_type is not a string")]
    #[explain(id = "not_compatible.reference_not_string")]
    ReferenceNotString {
        /// The claim the placeholder names.
        placeholder: ClaimIndex,
    },
    /// Every locale lost an entry to a template's absent claim (View §3 template).
    #[error("every locale lost an entry to a template's absent claim")]
    #[explain(id = "not_compatible.templates_exhausted")]
    TemplatesExhausted,
    /// A label that breaks §3.3 once rendered (View §2).
    #[error("{at}: {violation}")]
    #[explain(id = "not_compatible.rendered_label")]
    RenderedLabel {
        /// Which label.
        at: RenderedAt,
        /// The violation.
        #[source]
        violation: LabelViolation,
    },
    /// More rendered items than the wallet's bound (View §2).
    #[error("{items} rendered items, over the bound {bound}")]
    #[explain(id = "not_compatible.too_many_items")]
    TooManyItems {
        /// The rows and UI elements.
        items: usize,
        /// The bound.
        bound: ItemBound,
    },
    /// A field the Payment rulebook requires is absent (Payment §1).
    #[error("required {} absent", .member.repr_text())]
    #[explain(id = "not_compatible.payment_required")]
    PaymentRequired {
        /// The field.
        member: ReprItem,
    },
    /// A Generic payload of more than 11 properties (Generic §3).
    #[error("more than 11 payload properties")]
    #[explain(id = "not_compatible.generic_properties")]
    GenericProperties,
    /// A Generic payload without a non-empty string `transaction_id` (Generic §3).
    #[error("transaction_id absent")]
    #[explain(id = "not_compatible.generic_transaction_id")]
    GenericTransactionId,
    /// A Generic custom claim that is neither a string nor `null` (Generic §3.1).
    #[error("custom claim {claim}: not a string or null")]
    #[explain(id = "not_compatible.generic_custom")]
    GenericCustom {
        /// The claim's name.
        claim: String,
    },
    /// A Generic embedded payment payload without a field the Payment rulebook requires
    /// (Generic §3.2).
    #[error("payment_payload {} absent", .member.repr_text())]
    #[explain(id = "not_compatible.generic_payment")]
    GenericPayment {
        /// The field.
        member: ReprItem,
    },
    /// A Mandate embedded payment payload without a field the Payment rulebook requires
    /// (Mandate §2.2).
    #[error("payment_payload {} absent", .member.repr_text())]
    #[explain(id = "not_compatible.mandate_payment")]
    MandatePayment {
        /// The field.
        member: ReprItem,
    },
    /// `risk_signal_profiles` that is no array of profile identifiers (Risk Signals §3.2).
    #[error("risk_signal_profiles is not an array of profile identifiers")]
    #[explain(id = "not_compatible.risk_profiles")]
    RiskProfiles,
    /// A risk signal profile the wallet does not hold (Risk Signals §4.1).
    #[error("the wallet holds no risk signal profile {profile}")]
    #[explain(id = "not_compatible.unknown_risk_profile")]
    UnknownRiskProfile {
        /// The profile's identifier.
        profile: String,
    },
    /// `risk_signals` that is no array (Risk Signals §4.1).
    #[error("risk_signals is not an array")]
    #[explain(id = "not_compatible.risk_signals_not_array")]
    RiskSignalsNotArray,
    /// A malformed `risk_signals` entry (Risk Signals §3.4, §4.1).
    #[error("risk_signals entry {} is malformed", .signal.repr_text())]
    #[explain(id = "not_compatible.risk_signal_malformed")]
    RiskSignalMalformed {
        /// The entry as written.
        signal: ReprItem,
    },
    /// `encrypted` that is no boolean (Risk Signals §7.2).
    #[error("encrypted is not a boolean")]
    #[explain(id = "not_compatible.encrypted_not_boolean")]
    EncryptedNotBoolean,
    /// The risk signals must be encrypted and the issuer publishes no key the wallet can use
    /// (Risk Signals §7.3).
    #[error(
        "its risk signals must be encrypted and the issuer publishes no key the wallet can use"
    )]
    #[explain(id = "not_compatible.no_encryption_key")]
    NoEncryptionKey,
    /// The response needs a module phase 2 found the build lacks: an mdoc's encrypted risk
    /// signals need `COSE_Encrypt` (Risk Signals §7.6).
    #[error("its response needs the {module} module, which the build lacks")]
    #[explain(id = "not_compatible.lacks")]
    Lacks {
        /// The module.
        module: OptionalModule,
    },
    /// The ad-hoc metadata JWT fails a check (Proof Metadata §5.3).
    #[error("ad-hoc metadata: {failure}")]
    #[explain(id = "not_compatible.adhoc")]
    Adhoc {
        /// The check the JWT fails.
        #[from]
        failure: AdhocFailure,
    },
}

impl NotCompatible {
    /// The clause that decides it.
    #[must_use]
    pub const fn clause(&self) -> Clause {
        Clause::cited(match self {
            Self::ValueType { .. } | Self::Value { .. } | Self::ImageNotString { .. } => "View §3",
            Self::PayloadNotObject => "Core §7.1",
            Self::Mismatch(_) | Self::Uncovered { .. } | Self::MandatoryAbsent { .. } => {
                "Core §7.4.2 step 2"
            }
            Self::Image { .. } => "View §3 image; Core §7.4.2 step 3",
            Self::PayloadDirectional { .. } => "Proof Metadata §3.3",
            Self::TemplateNotString { .. }
            | Self::ForbiddenReference { .. }
            | Self::MoreNulls { .. }
            | Self::ReferenceNotString { .. }
            | Self::TemplatesExhausted => "View §3 template",
            Self::RenderedLabel { .. } => "View §2; Proof Metadata §3.3",
            Self::TooManyItems { .. } => "View §2",
            Self::PaymentRequired { .. } => "Payment §1; Core §7.4.2 step 2",
            Self::GenericProperties | Self::GenericTransactionId => "Generic §3",
            Self::GenericCustom { .. } => "Generic §3.1",
            Self::GenericPayment { .. } => "Generic §3.2; Payment §1",
            Self::MandatePayment { .. } => "Mandate §2.2; Payment §1",
            Self::RiskProfiles => "Risk Signals §3.2",
            Self::UnknownRiskProfile { .. } | Self::RiskSignalsNotArray => "Risk Signals §4.1",
            Self::RiskSignalMalformed { .. } => "Risk Signals §3.4; §4.1",
            Self::EncryptedNotBoolean => "Risk Signals §7.2",
            Self::NoEncryptionKey => "Risk Signals §7.3",
            Self::Lacks { .. } => "Risk Signals §7.6",
            Self::Adhoc { .. } => "Proof Metadata §5.3",
        })
    }
}

/// Which rendered label breaks §3.3. An error's argument writes it in English through `Display`;
/// a wallet words it through its statement.
#[derive(Debug, Clone, PartialEq, Eq, Message)]
pub enum RenderedAt {
    /// A claim's label at a payload path.
    #[message(id = "rendered_at.claim")]
    Claim {
        /// The claim's path.
        claim: ReprItem,
    },
    /// A UI label.
    #[message(id = "rendered_at.ui")]
    Ui {
        /// The UI label.
        key: UiKey,
    },
}

impl fmt::Display for RenderedAt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Claim { claim } => write!(f, "claim {} label", claim.repr_text()),
            Self::Ui { key } => write!(f, "ui_labels.{key}"),
        }
    }
}

/// No locale of the wallet's list completes every display array: the credential is excluded
/// (View §4).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[error("no locale of {} matches every display array", quoted(.locales))]
#[explain(id = "excluded")]
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
