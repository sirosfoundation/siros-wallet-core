//! OpenID4VP 1.0 transaction data for the SIROS wallet core, on the PaSO model (PaSO Core, View
//! and Proof Metadata, draft 2), with the four types of EC TS12 v1.0.1 as built-in rulebooks.
//!
//! | Requirement | API |
//! | --- | --- |
//! | One definition form: a `transaction_data_types` entry (Proof Metadata, Section 3), its labels typed by role, their limits and character rules set by the source ([`LabelRules`]: PaSO's Section 3.3, or TS12's Section 3.3.3), its structural rules (Section 3.3) | [`Definition`], [`ClaimDefinition`], [`UiLabels`], [`LabelText`], [`ValueType`] |
//! | Sources, each a parser into it: the signed credential metadata JWT (Sections 4 and 7), TS12 v1.0.1 type metadata (`lang` → `locale`, `label` → `name`, `visualisation` as [`Prominence`]), the host's [`Configuration`], and the entry's ad-hoc metadata JWT (Section 5). Ad-hoc first; then the credential's own metadata, which declares every type it supports and fails closed; else, for a credential known to have no metadata of its own, the configuration | [`SourceKind`], [`Configuration::parse`] |
//! | Metadata is input: the host holds signed credential metadata, Type Metadata and key sets, resolved and renewed outside presentations, and records what is absent (Proof Metadata, Sections 6 and 8); the wallet verifies each every time it loads it | [`HeldMetadata`], [`HeldDocument::absent`], [`HeldJwt::admit`], [`HeldMetadata::wanted`] |
//! | The projection to the wallet's language: one entry per array, made only by the locale function (View, Section 4), with its source and rulebook, written deterministically and read back | [`Definition::project`], [`Projected::to_json`], [`Projected::parse`], [`SourceInputs::served`] |
//! | T1: entries: base64url JSON without repeated names, `type`, `credential_ids` of DCQL query ids, `payload`, ad-hoc `metadata`, `transaction_data_hashes_alg` as an array or CS-12's string | [`Entry::parse`] |
//! | The request's rules: PaSO-targeted entries only in a signed request (Core, Section 3); the targeted queries in one credential set, its alternatives transposable (Core, Section 7.4.1) | [`check_request`] |
//! | Payload conformance: coverage, `#integrity` companions of images, mandatory claims, value types (Core, Section 7.4.2; View, Section 3) | [`PayloadFault`], [`Scalar`] |
//! | Images, by their form: a base64 Data URL of PNG, JPEG or SVG of at most 512 KiB, or an `https` URL with the integrity values of its `#integrity` sibling, which a TS12 logo may lack (View, Section 3; TS12, Section 4.3.1); over the Digital Credentials API, a Data URL of a format Credential Manager shows. The view carries each image to the UI, which resolves, verifies and renders it; the core resolves and verifies no image content. A TS12 logo that is not admitted is left out | [`Image`], [`ImageRef`], [`Channel`], [`ImageFault`], [`TransactionView::absent_images`] |
//! | Generic rendering: rows in claims order, `null` paths, `template:` as segments of text and typed values, label limits after interpolation, at most 200 items, `security_hint` as given (View, Section 2) | [`TransactionView`], [`Segment`], [`RenderFault`] |
//! | Selection: each candidate credential takes its first compatible entry (Core, Section 7.4.2) | [`Selector::first_match`] over [`Definitions`], [`Context::first_match`], [`Selection`] |
//! | The registration of a credential's sources: for each type a source names, the projected definition or why there is none, and one reason for every other type (K1); the picker's selection over it, which defers to the wallet an entry with ad-hoc metadata (K2) | [`SourceInputs::served_types`], [`ServedTypes`], [`Unserved`], [`Selector::first_match_unverified`], [`Deferral`] |
//! | T7: the B.3.3.1 hash over the entry as received, one algorithm per credential, `transaction_data_hashes_alg` repeated when the request carried it; `jti`, `response_mode` and `amr` under a TS12 rulebook; SD-JWT VC only | [`Binding::kb_jwt_claims`], [`Amr`] |
//!
//! Every refusal of a request is a [`TransactionDataError`]; every reason an entry does not
//! serve a credential is an [`Incompatibility`].
//!
//! Without the default feature `wallet` the crate holds the selection over a registration for the
//! credential picker (K2): definitions, the projection reader, payload conformance, selection over
//! [`Definitions`], and rendering. It links no X.509, ECDSA or trust code. The picker cannot
//! verify an entry's ad-hoc metadata JWT, which needs the trust store: the wallet verifies it
//! after the pick.

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

mod amr;
#[cfg(feature = "wallet")]
mod context;
mod currency;
mod definition;
mod entry;
mod error;
mod hash;
mod image;
mod integrity;
mod json;
mod output;
mod payload;
mod payment;
mod projection;
mod render;
mod select;
mod served;
mod sets;
mod sources;
mod ts12;
mod type_id;
mod view;

pub use amr::{Amr, AmrCategories, Factor, Inherence, Knowledge, Possession};
#[cfg(feature = "wallet")]
pub use context::{Context, SourceInputs};
pub use currency::CurrencyCode;
pub use definition::{
    grapheme_clusters, ActionLabel, BaseType, ClaimDefinition, ClaimDisplay, ClaimFault,
    ClaimIndex, ClaimName, Definition, DefinitionError, DefinitionMember, Description, EntryFault,
    HintEntry, LabelFormat, LabelLength, LabelRole, LabelRules, LabelText, LabelsFault, Limit,
    Localizations, Mandatory, OtherUiElement, PayloadPath, Prominence, SecurityHint, TextFault,
    TransactionTitle, UiElementKey, UiLabel, UiLabels, ValueType, MAX_CLAIMS,
};
pub use entry::Entry;
pub use error::{EntryMember, EntryPosition, EntryRefusal, TransactionDataError};
pub use hash::{AlgClaim, HashAlg, HashesAlgFault};
pub use image::{
    Channel, Image, ImageFault, ImageFormat, ImageRef, MAX_IMAGE_BYTES, MAX_IMAGE_PIXELS,
};
pub use integrity::{Integrity, IntegrityFault};
pub use output::{Binding, Jti, KbJwtInputs};
pub use payload::{
    CurrencyAmount, Frequency, IsoDateTime, IsoTime, Location, NumberText, PayloadFault,
    PayloadText, Scalar, Step as LocationStep, Typed, ValueFault,
};
pub use payment::{Payment, PaymentAmount};
pub use projection::{Projected, ProjectedClaim, ProjectionError, ProjectionMember, Unmatched};
pub use render::{RenderFault, TemplateFault, MAX_ITEMS};
pub use select::{Deferral, Definitions, Exclusion, Incompatibility, Selection, Selector, Taken};
pub use served::{ServedTypes, TypeRepeated, Unserved};
pub use sets::{SetPosition, SetsFault};
pub use sources::{
    AdHocMetadata, Configuration, ConfigurationError, ConfigurationMember, Configured,
    ConfiguredFault, ConfiguredType, CredentialSource, Rulebook, SourceKind,
};
#[cfg(feature = "wallet")]
pub use sources::{
    CredentialMetadataFault, HeldDocument, HeldError, HeldJwt, HeldMetadata, JwkFault, JwsFault,
    KeySetFault, MetadataClaim, Renewal, SignedFault, Ts12Fault, Ts12Member, Wanted, WantedFault,
};
pub use ts12::read::{MemberPath, Ts12PayloadFault};
pub use type_id::{EmptyTypeId, Ts12Type, TypeFamily, TypeId};
pub use view::{
    Interpolated, Row, RowValue, Segment, ShownLabel, TransactionView, UnsignedWarning,
};

/// Checks the request's rules on its `entries` as a whole: an unsigned request carries no
/// PaSO-targeted entry (PaSO Core, Section 3), and the credential sets of `query` hold the
/// queries the entries target as Section 7.4.1 says.
///
/// # Errors
///
/// [`TransactionDataError::Unsigned`] and [`TransactionDataError::CredentialSets`].
pub fn check_request(
    entries: &[Entry],
    query: &siros_dcql::DcqlQuery,
    signature: siros_oid4vp::RequestSignature,
) -> Result<(), TransactionDataError> {
    if signature == siros_oid4vp::RequestSignature::Unsigned {
        if let Some(entry) = entries
            .iter()
            .find(|e| e.type_id().family() == TypeFamily::Paso)
        {
            return Err(TransactionDataError::Unsigned(entry.position()));
        }
    }
    sets::check(entries, query).map_err(TransactionDataError::CredentialSets)
}
