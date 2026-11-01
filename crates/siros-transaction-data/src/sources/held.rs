//! The metadata the host holds for transaction data (PaSO Proof Metadata, Sections 6 and 8). The
//! host resolves and renews it outside presentations, because resolving it during a
//! presentation tells the publisher which credential is presented. The wallet verifies each
//! document every time it loads it.
//!
//! What the host holds, for each credential:
//!
//! - the issuer metadata of its configuration, in the [`DisplayCache`];
//! - when that configuration names a `credential_metadata_uri`, the signed credential metadata
//!   JWT it serves in the wallet's language, admitted by [`HeldJwt::admit`] with the URL that
//!   served it; the host renews it before the [`Renewal`]'s expiry, from the URL the
//!   [`Renewal`] names (Section 8);
//! - when the credential is an SD-JWT VC whose `vct` is an `https` URL, the Type Metadata at that
//!   URL and the documents its `transaction_data_types` entries reference (EC TS12 v1.0.1,
//!   Section 4.1). The credential's `#integrity` claims pin them, so they change only with the
//!   credential;
//! - when the credential carries no `x5c` chain, its issuer's JWT VC Issuer Metadata and the key
//!   set its `jwks_uri` names (SD-JWT VC, Section 4.3).
//!
//! A URL that serves no document the host records as absent ([`HeldDocument::absent`]): the
//! wallet tells a document the issuer does not publish from one the host never resolved, which
//! it does not read as absent. [`HeldMetadata::wanted`] lists what the host should hold for a
//! credential and does not.

use rustc_hash::FxHashMap;
use siros_codec::date::DateTime;
use siros_credential::Credential;
use siros_display::DisplayCache;
use siros_oid4vp::HttpsUrl;
use siros_trust::TrustStore;
use siros_wallet_state::{ConfigurationId, IssuerIdentifier};

use super::issuer_keys::{self, KeySetFault};
use super::paso::CredentialMetadata;
use super::signed::Verifier;
use super::ts12::{Ts12Fault, TypeMetadata};

/// A signed credential metadata JWT the host holds for a credential configuration, with the URL
/// it answered from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldJwt {
    issuer: IssuerIdentifier,
    configuration: ConfigurationId,
    jwt: String,
    served_from: HttpsUrl,
}

/// A document the host holds, by the URL that served it, or its record that the URL serves
/// none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldDocument {
    url: HttpsUrl,
    content: Content,
}

/// What the host holds for a URL.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Content {
    /// The document.
    Body(Vec<u8>),
    /// The URL serves no document.
    Absent,
}

/// What the host holds for a URL, as the wallet reads it.
pub(crate) enum Holding<'h> {
    /// The document.
    Body(&'h [u8]),
    /// The host's record that the URL serves no document.
    Absent,
    /// Nothing: the host never resolved the URL.
    NotHeld,
}

impl HeldDocument {
    /// The document `body` that `url` served.
    #[must_use]
    pub fn new(url: HttpsUrl, body: Vec<u8>) -> Self {
        Self {
            url,
            content: Content::Body(body),
        }
    }

    /// The host's record that `url` serves no document.
    #[must_use]
    pub fn absent(url: HttpsUrl) -> Self {
        Self {
            url,
            content: Content::Absent,
        }
    }
}

/// What a host can renew a signed credential metadata JWT by: when it expires, and the
/// `credential_metadata_uri` it names (Section 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renewal {
    pub(crate) expires: DateTime,
    pub(crate) from: HttpsUrl,
}

impl Renewal {
    /// The JWT's `exp`: the host obtains a new one before it.
    #[must_use]
    pub fn expires(&self) -> DateTime {
        self.expires
    }

    /// The JWT's `credential_metadata_uri`, which serves the next one.
    #[must_use]
    pub fn from(&self) -> &HttpsUrl {
        &self.from
    }
}

/// Why the host's metadata does not read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum HeldError {
    /// Two JWTs are held for this credential configuration.
    JwtRepeated(IssuerIdentifier, ConfigurationId),
    /// Two documents are held for this URL.
    DocumentRepeated(HttpsUrl),
}

impl HeldError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::JwtRepeated(..) => "held_jwt_repeated",
            Self::DocumentRepeated(_) => "held_document_repeated",
        }
    }
}

/// The metadata the host holds: a signed credential metadata JWT per credential configuration,
/// and documents by URL.
#[derive(Debug, Clone, Default)]
pub struct HeldMetadata {
    jwts: FxHashMap<(IssuerIdentifier, ConfigurationId), HeldJwt>,
    documents: FxHashMap<HttpsUrl, Content>,
}

impl HeldMetadata {
    /// The metadata of `jwts` and `documents`.
    ///
    /// # Errors
    ///
    /// [`HeldError`]: two JWTs of one configuration, or two documents of one URL.
    pub fn new(jwts: Vec<HeldJwt>, documents: Vec<HeldDocument>) -> Result<Self, HeldError> {
        let mut held = Self::default();
        for jwt in jwts {
            let key = (jwt.issuer.clone(), jwt.configuration.clone());
            if held.jwts.insert(key.clone(), jwt).is_some() {
                let (issuer, configuration) = key;
                return Err(HeldError::JwtRepeated(issuer, configuration));
            }
        }
        for HeldDocument { url, content } in documents {
            if held.documents.insert(url.clone(), content).is_some() {
                return Err(HeldError::DocumentRepeated(url));
            }
        }
        Ok(held)
    }

    /// The signed credential metadata JWT held for `credential`'s configuration.
    pub(crate) fn jwt(&self, credential: &Credential) -> Option<&HeldJwt> {
        let key = (
            credential.issuer()?.clone(),
            credential.configuration_id()?.clone(),
        );
        self.jwts.get(&key)
    }

    /// What the host holds for `url`.
    pub(crate) fn document(&self, url: &HttpsUrl) -> Holding<'_> {
        match self.documents.get(url) {
            Some(Content::Body(body)) => Holding::Body(body),
            Some(Content::Absent) => Holding::Absent,
            None => Holding::NotHeld,
        }
    }

    /// What the host should hold for `credential` and does not, in the order the wallet reads
    /// it: its issuer metadata in `display`; its signed credential metadata, or a new one where
    /// the JWT held does not verify against `trust` at `now` (Section 6); and the documents
    /// it has neither resolved nor recorded as absent. The host resolves each; a URL that serves
    /// no document it records with [`HeldDocument::absent`].
    ///
    /// # Errors
    ///
    /// [`WantedFault`]: a held document that does not read, so that the documents it
    /// references are unknown.
    pub fn wanted(
        &self,
        credential: &Credential,
        display: &DisplayCache,
        trust: &TrustStore,
        now: DateTime,
    ) -> Result<Vec<Wanted>, WantedFault> {
        let mut wanted = Vec::new();
        match display.issuer_metadata(credential) {
            None => wanted.push(Wanted::IssuerMetadata),
            Some(issued) => {
                if let Some(uri) = issued.credential_metadata_uri() {
                    let verifier = Verifier {
                        trust,
                        held: self,
                        now,
                    };
                    if CredentialMetadata::load(credential, verifier).is_err() {
                        let from = self.jwt(credential).map_or(uri, |held| &held.served_from);
                        wanted.push(Wanted::CredentialMetadata(from.clone()));
                    }
                }
            }
        }
        let referenced =
            TypeMetadata::documents(credential, self).map_err(WantedFault::TypeMetadata)?;
        let keys = match credential.issuer_chain() {
            Some(_) => Vec::new(),
            None => credential
                .issuer()
                .map(|issuer| issuer_keys::documents(issuer, self))
                .transpose()
                .map_err(WantedFault::KeySet)?
                .unwrap_or_default(),
        };
        wanted.extend(
            referenced
                .into_iter()
                .chain(keys)
                .filter(|url| matches!(self.document(url), Holding::NotHeld))
                .map(Wanted::Document),
        );
        Ok(wanted)
    }
}

impl HeldJwt {
    /// The JWT `jwt` the host holds for the configuration `configuration` of `issuer`, served by
    /// `served_from`. The wallet verifies it each time it loads it: Section 7, and its
    /// `credential_metadata_uri` against `served_from` (Section 8).
    #[must_use]
    pub fn new(
        issuer: IssuerIdentifier,
        configuration: ConfigurationId,
        jwt: String,
        served_from: HttpsUrl,
    ) -> Self {
        Self {
            issuer,
            configuration,
            jwt,
            served_from,
        }
    }

    /// The configuration's issuer.
    #[must_use]
    pub fn issuer(&self) -> &IssuerIdentifier {
        &self.issuer
    }

    /// The configuration.
    #[must_use]
    pub fn configuration(&self) -> &ConfigurationId {
        &self.configuration
    }

    /// The JWT.
    #[must_use]
    pub fn jwt(&self) -> &str {
        &self.jwt
    }

    /// The URL that served the JWT.
    #[must_use]
    pub fn served_from(&self) -> &HttpsUrl {
        &self.served_from
    }
}

/// What the host should hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wanted {
    /// The issuer metadata of the credential's configuration (OpenID4VCI 1.0, Section 12.2).
    IssuerMetadata,
    /// The signed credential metadata JWT this URL serves.
    CredentialMetadata(HttpsUrl),
    /// The document at this URL.
    Document(HttpsUrl),
}

/// Why the documents a held document references are unknown.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum WantedFault {
    /// The held Type Metadata does not read.
    TypeMetadata(#[source] Ts12Fault),
    /// The held JWT VC Issuer Metadata does not read.
    KeySet(#[source] KeySetFault),
}

impl WantedFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::TypeMetadata(fault) => fault.code(),
            Self::KeySet(fault) => fault.code(),
        }
    }
}
