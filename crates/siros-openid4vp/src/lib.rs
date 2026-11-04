//! OpenID4VP 1.0 for the SIROS wallet core.
//!
//! The crate owns the protocol and DCQL; format and transaction data plug-ins own everything
//! format- or type-specific, behind the traits of [`plugins`].
//!
//! - [`request`]: the request as received over the DC API, its Credential Queries, Credential
//!   Sets and `transaction_data` entries, the alternatives the sets allow and their factoring.
//! - [`plugins`]: the format and transaction data profile contracts and the [`plugins::Registry`].
//! - [`wallet`]: the credentials as the wallet registers them.
//! - [`rows`], [`text`], [`boxes`]: what plug-ins render into, and the text rules the core applies.
//! - [`ids`], [`json`], [`refusal`]: the identifiers, JSON with unique member names, and refusals
//!   with their error codes.
//! - [`claims`]: DCQL claims and `claim_sets`, shared by the formats that use them.
//! - [`hash`], [`sri`]: OpenID4VP B.3.3.1 hashes over the registered algorithms, W3C SRI.
//! - [`arrival`], [`jose`], [`envelope`], [`routing`], [`modes`]: the request as received over the
//!   DC API or by URI, the JWS and JWE it arrives in, its parameters and signatures as read, what
//!   it asks of its answer, and OpenID4VP's response modes.
//! - [`matching`] (feature `match`): phase 1, the request rules, matching, consent, the display
//!   and the records its entries carry.
//! - [`uri`], [`authenticate`], [`recourse`] (feature `resolve`): a request by URI and the fetch
//!   of its Request Object, the Verifier's authentication through its Client Identifier Prefix,
//!   and where a request refused before it goes.
//! - [`resolve`], [`effects`], [`host`], [`session`] (feature `resolve`): phase 2, the response
//!   to the records the user chose, the questions it asks its caller, the host's modules it and
//!   the plug-ins call, and what binds a presentation to its request.
//! - [`wallet_metadata`] (feature `resolve`): the metadata the wallet posts for a Request Object.
//! - [`cbor`] (feature `resolve`): CBOR with distinct map keys, its conversions with JSON, and
//!   COSE through the re-exported coset.

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
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

pub mod arrival;
pub mod boxes;
pub mod claims;
pub mod envelope;
pub mod hash;
pub mod ids;
pub mod jose;
pub mod json;
pub mod modes;
pub mod plugins;
mod product;
pub mod refusal;
pub mod request;
pub mod routing;
pub mod rows;
pub mod sri;
pub mod text;
pub mod wallet;

/// The core's domain, as its fault message.
pub(crate) const FAULT: plugins::FaultDomain =
    siros_explain::checked!(plugins::FaultDomain, "openid4vp.fault");

/// The core's messages: those its error types declare, and its fault's. A transparent variant
/// declares its cause's messages too.
pub struct CrateMessages;

impl siros_explain::Messages for CrateMessages {
    fn messages() -> Vec<siros_explain::Message> {
        let declared: &[fn() -> Vec<siros_explain::Message>] = &[
            ids::InvalidId::messages,
            wallet::RegistrationError::messages,
            json::JsonError::messages,
            claims::PathError::messages,
            claims::ClaimsError::messages,
            claims::kit::KitRule::messages,
            claims::kit::QueryRule::<claims::kit::KitRule>::messages,
            claims::kit::NoAlgorithm::messages,
            request::Malformed::messages,
            request::MetadataError::messages,
            request::StructureRule::messages,
            request::UndecodedEntry::messages,
            request::DcqlRule::messages,
            refusal::Refused::messages,
            plugins::RegistryError::messages,
            plugins::MemberTwice::messages,
            plugins::NoCandidate::messages,
            plugins::NotOffered::messages,
            plugins::AttestedTwice::messages,
            rows::BadValue::messages,
            rows::EnvError::messages,
            rows::NotHttpsUrl::messages,
            rows::NoALabel::messages,
            hash::HashesAlgRule::messages,
            arrival::Unreadable::messages,
            arrival::DataShape::messages,
            arrival::UriError::messages,
            arrival::FetchFailure::messages,
            jose::JwsError::messages,
            jose::JweError::messages,
            #[cfg(feature = "resolve")]
            jose::NotPublicJwk::messages,
            #[cfg(feature = "resolve")]
            jose::SkewTooLarge::messages,
            #[cfg(feature = "resolve")]
            jose::TimeError::messages,
            routing::RoutingRule::messages,
            modes::KeyRule::messages,
            #[cfg(feature = "match")]
            matching::CoreRule::messages,
            #[cfg(feature = "match")]
            matching::RecordError::messages,
            #[cfg(feature = "match")]
            matching::SelectionError::messages,
            #[cfg(feature = "resolve")]
            plugins::InformError::messages,
            #[cfg(feature = "resolve")]
            hash::HashesError::messages,
            #[cfg(feature = "resolve")]
            host::NotSealed::messages,
            #[cfg(feature = "resolve")]
            host::SignFailed::messages,
            #[cfg(feature = "resolve")]
            host::SignatureInvalid::messages,
            #[cfg(feature = "resolve")]
            host::DecryptFailed::messages,
            #[cfg(feature = "resolve")]
            host::PresentError::messages,
            #[cfg(feature = "resolve")]
            effects::NotMediaType::messages,
            #[cfg(feature = "resolve")]
            cbor::CborError::messages,
            #[cfg(feature = "resolve")]
            cbor::cose::CoseShape::messages,
            #[cfg(feature = "resolve")]
            resolve::Rejection::messages,
            #[cfg(feature = "resolve")]
            authenticate::Unauthenticated::messages,
            #[cfg(feature = "resolve")]
            authenticate::PrefixRefusal::messages,
            #[cfg(feature = "resolve")]
            authenticate::Unbound::messages,
            #[cfg(feature = "resolve")]
            authenticate::OutsideValidity::messages,
            #[cfg(feature = "resolve")]
            recourse::Failure::messages,
            #[cfg(feature = "resolve")]
            uri::NotHttps::messages,
            #[cfg(feature = "resolve")]
            uri::NotUri::messages,
            #[cfg(feature = "resolve")]
            uri::NoFetch::messages,
            #[cfg(feature = "resolve")]
            resolve::Outcome::messages,
        ];
        declared
            .iter()
            .flat_map(|messages| messages())
            .chain([FAULT.message()])
            .collect()
    }
}

/// The items given, which exist when the core's phase 2 does (feature `resolve`). A plug-in
/// crate writes its phase-2 code inside it, so the code follows the core's features as Cargo
/// unifies them.
#[cfg(feature = "resolve")]
#[macro_export]
macro_rules! with_resolve {
    ($($item:tt)*) => { $($item)* };
}

/// The items given, which exist when the core's phase 2 does (feature `resolve`). A plug-in
/// crate writes its phase-2 code inside it, so the code follows the core's features as Cargo
/// unifies them.
#[cfg(not(feature = "resolve"))]
#[macro_export]
macro_rules! with_resolve {
    ($($item:tt)*) => {};
}

/// The items given, which exist when the core's phase 2 does not: the counterpart of
/// [`with_resolve!`].
#[cfg(feature = "resolve")]
#[macro_export]
macro_rules! without_resolve {
    ($($item:tt)*) => {};
}

/// The items given, which exist when the core's phase 2 does not: the counterpart of
/// [`with_resolve!`].
#[cfg(not(feature = "resolve"))]
#[macro_export]
macro_rules! without_resolve {
    ($($item:tt)*) => { $($item)* };
}

#[cfg(feature = "resolve")]
pub mod authenticate;
#[cfg(feature = "resolve")]
pub mod cbor;
#[cfg(feature = "resolve")]
pub mod effects;
#[cfg(feature = "resolve")]
pub mod host;
#[cfg(feature = "match")]
pub mod matching;
#[cfg(feature = "resolve")]
pub mod recourse;
#[cfg(feature = "resolve")]
pub mod resolve;
#[cfg(feature = "resolve")]
pub mod session;
#[cfg(feature = "resolve")]
pub mod uri;
#[cfg(feature = "resolve")]
pub mod wallet_metadata;
