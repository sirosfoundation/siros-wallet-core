//! OpenID4VP 1.0 for the SIROS wallet core.
//!
//! The crate owns the protocol and DCQL; format and transaction data plug-ins own everything
//! format- or type-specific, behind the traits of [`plugins`].
//!
//! - [`request`]: the request as received over the DC API, its Credential Queries, Credential
//!   Sets and `transaction_data` entries, the alternatives the sets allow and their factoring.
//! - [`plugins`]: the format and transaction data profile contracts and the [`plugins::Registry`].
//! - [`wallet`]: the credentials as the wallet registers them.
//! - [`rows`], [`text`], [`consent`]: what plug-ins render into, the text rules the core applies,
//!   and the consent entry as platform-neutral data.
//! - [`ids`], [`json`], [`media`], [`refusal`]: the identifiers, JSON with unique member names,
//!   media types, and refusals with their error codes.
//! - [`claims`]: DCQL claims and `claim_sets`, shared by the formats that use them; its `kit`
//!   under the feature `claims`.
//! - [`arrival`], [`jose`], [`envelope`], [`routing`], [`modes`]: the request as received over the
//!   DC API or by URI, the JWS and JWE it arrives in, its parameters and signatures as read, what
//!   it asks of its answer, and OpenID4VP's response modes.
//! - [`uri`], [`wallet_metadata`], [`scope`]: a request by URI, the fetch of its Request Object,
//!   the metadata the wallet posts for it and the scope values that stand for DCQL queries.
//! - [`hash`]: OpenID4VP B.3.3.1 hashes over the registered algorithms.
//! - `matching` (feature `match`): phase 1, the request rules, matching, consent, the display
//!   and the records its entries carry.
//! - `authenticate`, `recourse`, `resolve`, `effects`, `host`, `session` (feature `resolve`):
//!   the Verifier's authentication through its Client Identifier Prefix, where a request refused
//!   before it goes, phase 2, the questions it asks its caller, the host's modules it and the
//!   plug-ins call, and what binds a presentation to its request.
//! - `sri` (feature `sri`): W3C Subresource Integrity.
//! - `cbor` (feature `cbor`): CBOR with distinct map keys, its conversions with JSON, and COSE
//!   through the re-exported coset.
//!
//! # Features
//!
//! Each mechanism compiles under the feature of the crates that use it, and a build compiles
//! what it registers. A feature adds types, trait implementations, methods and modules, and
//! changes no signature.
//!
//! | Feature | Holds |
//! | :-- | :-- |
//! | `match` | phase 1 |
//! | `resolve` | phase 2; implies `match` |
//! | `dc-api` | `Received::dc_api`; the modes `dc_api` and `dc_api.jwt` |
//! | `uri` | the URI parsers, the fetch, the POST and its contributions, the Response URI's answer, scope queries; the modes `direct_post.jwt` and `direct_post`; implies `signed` and `resolve` |
//! | `signed` | Client Identifier Prefixes, the signature step of authentication, the rules on a Request Object's claims; implies `resolve` |
//! | `request-decryption` | encrypted Request Objects; implies `uri` |
//! | `cbor` | the `cbor` module and its COSE reading |
//! | `transaction-data` | B.3.3.1's hashes, the registered algorithms, `Sha2` |
//! | `sha3`, `blake2`, `k12` | `Sha3`, `Blake2`, `K12`; each implies `transaction-data` |
//! | `sri` | W3C SRI |
//! | `claims` | the claims kit |

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

siros_explain::scope!("openid4vp");

pub mod arrival;
pub mod claims;
pub mod consent;
pub mod envelope;
pub mod hash;
pub mod ids;
pub mod jose;
pub mod json;
pub mod media;
pub mod modes;
pub mod plugins;
mod product;
pub mod refusal;
pub mod request;
pub mod routing;
pub mod rows;
pub mod scope;
#[cfg(feature = "sri")]
pub mod sri;
pub mod text;
pub mod uri;
pub mod wallet;
pub mod wallet_metadata;

#[cfg(feature = "resolve")]
pub mod authenticate;
#[cfg(feature = "cbor")]
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
