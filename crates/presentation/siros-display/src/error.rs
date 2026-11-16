//! Why display refuses an input. Each error has a stable code.

use siros_dcql::{ClaimPathError, PathError};
use siros_zkp_req::ItemIndex;

use crate::locale::LocaleError;
use crate::text::TextError;

/// Why display refuses an input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum DisplayError {
    /// Text to show is unsafe or too long. The code is its own.
    Text(#[source] TextError),
    /// A `locale` is no language tag. The code is its own.
    Locale(#[source] LocaleError),
    /// A `zkp_req` option names this `_req` index, which its query lacks: the option is
    /// another query's.
    OptionItemUnknown(ItemIndex),
    /// A metadata document, or one of its members, is no JSON object.
    NotObject,
    /// `credential_issuer` is absent, no string, or empty.
    IssuerIdentifier,
    /// The Credential Issuer Metadata offers no configuration of that identifier.
    ConfigurationUnknown,
    /// `credential_configuration_id` is absent, no string, or empty.
    ConfigurationId,
    /// Issuer metadata carries `auxiliary_data`, which only a Credential Response may carry
    /// (privatedata 3.1, Section 5A.3).
    AuxiliaryDataPublished,
    /// The Credential Response's `credential_metadata` is no JSON object (privatedata 3.1,
    /// Section 5A.1).
    ResponseMetadataNotObject,
    /// The display metadata record has an unknown member.
    RecordMemberUnknown,
    /// `credential_metadata_uri` is no `https` URL (PaSO Proof Metadata, Section 2).
    CredentialMetadataUri,
    /// A `display` array or one of its entries breaks its rules.
    Display(#[source] EntryFault),
    /// Two `display` entries of one array have the same locale.
    DisplayLocaleRepeated,
    /// A `logo` breaks its rules.
    Logo(#[source] LogoFault),
    /// A colour is no numerical colour value of CSS Color Module Level 3.
    Colour(#[source] ColourFault),
    /// A `claims` array, a claim description or one of its `display` entries breaks its rules.
    Claims(#[source] EntryFault),
    /// A claim `path` is no claims path pointer.
    ClaimPath(#[source] ClaimPathError),
    /// Two claims descriptions address the same claim (OpenID4VCI 1.0, Appendix B.3).
    ClaimRepeated,
    /// Two claims descriptions disagree on whether a claim is an object or an array, or address
    /// one array both by `null` and by an index (OpenID4VCI 1.0, Appendix B.3).
    ClaimContradictory,
    /// The Type Metadata `vct` is absent or no string.
    Vct,
    /// The Type Metadata `extends` is no string.
    Extends,
    /// A claim metadata `svg_id` is no string of the syntax of SD-JWT VC, Section 5.6, or
    /// repeats one of the document.
    SvgId,
    /// A claim metadata `sd` is none of `always`, `allowed` and `never`.
    Sd,
    /// A claim metadata `mandatory` is no boolean.
    Mandatory,
    /// The display cache holds two entries of one credential configuration.
    IssuerMetadataRepeated,
    /// The display cache holds two Type Metadata documents of one `vct`.
    TypeMetadataRepeated,
    /// An `extends` names a type the display cache lacks.
    ExtendsUnknown,
    /// A chain of `extends` returns to its start (SD-JWT VC, Section 7.4).
    ExtendsCycle,
    /// A claims path pointer selects nothing in the credential. The code is its own.
    Pointer(#[source] PathError),
    /// A claims path pointer without `null` selects several claims.
    PointerSelectsSeveral,
    /// A claim has no label in the metadata and its path has no key.
    PointerUnlabelled,
    /// A number has no `f64` value.
    NumberUnrepresentable,
}

/// Why text is no numerical colour value of CSS Color Module Level 3, Section 4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ColourFault {
    /// The member is no string.
    #[error("the member is no string")]
    NotString,
    /// The text after `#` is other than three or six hexadecimal digits.
    #[error("the text after `#` is other than three or six hexadecimal digits")]
    Hexadecimal,
    /// The text has no `(`, or does not end with `)`.
    #[error("the text has no `(`, or does not end with `)`")]
    Notation,
    /// The function is none of `rgb`, `rgba`, `hsl` and `hsla` with its number of arguments; it
    /// has this many.
    #[error("the function is none of `rgb`, `rgba`, `hsl` and `hsla` with its number of arguments; it has {0}")]
    Function(usize),
    /// The argument at this position is no `<integer>`, `<number>` or `<percentage>` as its
    /// place takes.
    #[error("the argument at position {0} is no `<integer>`, `<number>` or `<percentage>` as its place takes")]
    Argument(usize),
}

/// The rule an array of metadata entries, or one of its entries, breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum EntryFault {
    /// The member is no array, or an empty one where it must hold an entry.
    #[error("the member is no array, or an empty one where it must hold an entry")]
    NotArray,
    /// An entry is no JSON object.
    #[error("an entry is no JSON object")]
    EntryNotObject,
    /// An entry lacks a member it requires.
    #[error("an entry lacks a member it requires")]
    MemberMissing,
    /// A member of an entry has the wrong JSON type.
    #[error("a member of an entry has the wrong JSON type")]
    MemberType,
}

/// The rule a `logo` breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum LogoFault {
    /// The logo is no JSON object.
    #[error("the logo is no JSON object")]
    NotObject,
    /// `uri` is absent, or no `https:` URL with an authority or `data:` URI of visible ASCII.
    #[error(
        "`uri` is absent, or no `https:` URL with an authority or `data:` URI of visible ASCII"
    )]
    Uri,
    /// `uri#integrity` is no non-empty string of visible ASCII and spaces.
    #[error("`uri#integrity` is no non-empty string of visible ASCII and spaces")]
    Integrity,
    /// `alt_text` is no string.
    #[error("`alt_text` is no string")]
    AltText,
}

impl DisplayError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Text(e) => e.code(),
            Self::Locale(e) => e.code(),
            Self::Pointer(e) => e.code(),
            Self::OptionItemUnknown(_) => "option_item_unknown",
            Self::NotObject => "metadata_not_object",
            Self::IssuerIdentifier => "credential_issuer_malformed",
            Self::ConfigurationUnknown => "configuration_unknown",
            Self::ConfigurationId => "configuration_id_malformed",
            Self::AuxiliaryDataPublished => "auxiliary_data_published",
            Self::ResponseMetadataNotObject => "response_metadata_not_object",
            Self::RecordMemberUnknown => "record_member_unknown",
            Self::CredentialMetadataUri => "credential_metadata_uri_malformed",
            Self::Display(_) => "display_malformed",
            Self::DisplayLocaleRepeated => "display_locale_repeated",
            Self::Logo(_) => "logo_malformed",
            Self::Colour(_) => "colour_malformed",
            Self::Claims(_) => "claims_malformed",
            Self::ClaimPath(_) => "claim_path_malformed",
            Self::ClaimRepeated => "claim_repeated",
            Self::ClaimContradictory => "claim_contradictory",
            Self::Vct => "vct_malformed",
            Self::Extends => "extends_malformed",
            Self::SvgId => "svg_id_malformed",
            Self::Sd => "sd_malformed",
            Self::Mandatory => "mandatory_malformed",
            Self::IssuerMetadataRepeated => "issuer_metadata_repeated",
            Self::TypeMetadataRepeated => "type_metadata_repeated",
            Self::ExtendsUnknown => "extends_unknown",
            Self::ExtendsCycle => "extends_cycle",
            Self::PointerSelectsSeveral => "pointer_selects_several",
            Self::PointerUnlabelled => "pointer_unlabelled",
            Self::NumberUnrepresentable => "number_unrepresentable",
        }
    }
}
