//! Display for the SIROS wallet core.
//!
//! | Requirement | API |
//! | --- | --- |
//! | D1: the only metadata merger; `auxiliary_data` leaves the Credential Response's `credential_metadata` before the merge | [`IssuerMetadata::merge`] |
//! | Display metadata: OpenID4VCI `credential_metadata` and SD-JWT VC Type Metadata, held by the host | [`IssuerMetadata`], [`TypeMetadata`], [`DisplayCache`] |
//! | D2: the locale function of every display array: RFC 4647 Lookup with the wallet's one language, then the entry without a locale (PaSO View, Section 4) | [`Locale`], [`lookup`] |
//! | D3: SD-JWT VC Type Metadata display wins; OpenID4VCI `credential_metadata` is the fallback | [`DisplayCache::card`], [`DisplayCache::claim_rows`] |
//! | D4: values typed for display | [`DisplayValue`] |
//! | A credential's claim labels in the wallet's language, which a registration projection carries to the credential picker (K1) | [`DisplayCache::claim_labels`], [`ClaimLabels`] |
//! | D5: bytes shown by their length | [`DisplayValue::Bytes`] |
//! | Credential cards and claim rows | [`Card`], [`ClaimRow`] |
//! | Display text: no control, format, bidi, separator, private-use or unassigned character, and no over-long text | [`DisplayText`] |
//! | Purpose lines (OpenID4VP 1.0, Section 6.2) | [`purpose::line`], [`purpose::display`] |
//! | Proof statement rows of a `zkp_req` option: the picker's, marked as unverified, and a verified request's | [`proof::rows`], [`proof::verified_rows`] |
//! | The credential picker's fields: a claim row or a proof statement as one short line, and whether a text was cut to fit (A9) | [`Field`], [`FieldText`], [`Extent`] |

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(unused_results)]
#![deny(clippy::cognitive_complexity)]
#![deny(clippy::let_underscore_must_use, clippy::let_underscore_untyped)]
// Nothing panics outside the tests. scripts/check_panic_sites.py refuses an
// allow of these lints there and finds the panics they cannot see.
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

mod error;
mod field;
mod labels;
mod locale;
pub mod proof;
pub mod purpose;
mod text;

pub use error::{ColourFault, DisplayError, EntryFault, LogoFault};
pub use field::{Extent, Field, FieldName, FieldText, FIELD_MAX};
pub use labels::{ClaimLabels, ClaimRow, DescribedLabel, DisplayValue};
pub use locale::{lookup, Locale, LocaleError, Localized};
pub use text::{
    CardText, DisplayText, IssuerTemplate, LabelText, TemplateError, TextError, CARD_TEXT_MAX,
    LABEL_MAX, TEMPLATE_MAX, VALUE_MAX,
};

#[cfg(feature = "credential")]
mod cache;
#[cfg(feature = "credential")]
mod card;
#[cfg(feature = "credential")]
mod claims;
#[cfg(feature = "credential")]
mod colour;
#[cfg(feature = "credential")]
mod entry;
#[cfg(feature = "credential")]
mod issuer;
#[cfg(feature = "credential")]
mod json;
#[cfg(feature = "credential")]
mod logo;
#[cfg(feature = "credential")]
mod rows;
#[cfg(feature = "credential")]
mod type_metadata;

#[cfg(feature = "credential")]
pub use cache::DisplayCache;
#[cfg(feature = "credential")]
pub use card::{Card, CardWording};
#[cfg(feature = "credential")]
pub use colour::Colour;
#[cfg(feature = "credential")]
pub use issuer::IssuerMetadata;
#[cfg(feature = "credential")]
pub use logo::{Integrity, Logo, LogoUri};
#[cfg(feature = "credential")]
pub use type_metadata::TypeMetadata;
