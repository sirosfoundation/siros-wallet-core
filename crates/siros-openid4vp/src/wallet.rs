//! The credentials as the wallet registers them: each with its format, its format plug-in's view,
//! the documents the wallet resolved for its plug-ins, and the facts the wallet resolved about it.

use siros_explain::Explain;

use crate::ids::{AuthorityType, AuthorityValue, CredentialId, DocumentKey, FormatId};
use crate::request::Query;

/// Whether a credential is bound to a key the wallet holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Holder {
    /// Bound to a key the wallet holds.
    Bound,
    /// Bound to no key.
    Unbound,
}

/// The values the wallet resolved for a credential under one Trusted Authorities type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldAuthority<'a> {
    /// The type.
    pub kind: AuthorityType<'a>,
    /// The values.
    pub values: Vec<AuthorityValue<'a>>,
}

/// What the wallet resolved about a credential at registration, for every plug-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts<'a> {
    /// Whether it is bound to a key the wallet holds.
    pub holder: Holder,
    authorities: Vec<HeldAuthority<'a>>,
}

/// Registration data that cannot exist.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.registration")]
pub enum RegistrationError {
    /// Two Trusted Authorities entries of one type.
    #[error("the facts list the trusted authority type {0} twice")]
    AuthorityTwice(#[explain(name = "authority_type")] String),
    /// Two documents under one key.
    #[error("credential {credential}: two documents under the key {key}")]
    DocumentTwice {
        /// The credential.
        credential: String,
        /// The key.
        key: String,
    },
    /// Two credentials with one id.
    #[error("two credentials have the id {0}")]
    CredentialTwice(#[explain(name = "credential")] String),
}

impl<'a> Facts<'a> {
    /// The facts, each Trusted Authorities type once.
    pub fn new(
        holder: Holder,
        authorities: Vec<HeldAuthority<'a>>,
    ) -> Result<Self, RegistrationError> {
        if let Some(twice) = authorities.iter().enumerate().find_map(|(k, a)| {
            authorities
                .get(..k)
                .and_then(|before| before.iter().find(|b| b.kind == a.kind))
        }) {
            return Err(RegistrationError::AuthorityTwice(twice.kind.to_string()));
        }
        Ok(Self {
            holder,
            authorities,
        })
    }

    /// The values held under a type.
    #[must_use]
    pub fn authority(&self, kind: &AuthorityType<'_>) -> Option<&HeldAuthority<'a>> {
        self.authorities.iter().find(|held| held.kind == *kind)
    }
}

/// A document a plug-in reads, under the plug-in's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document<'a> {
    /// The plug-in's key.
    pub key: DocumentKey<'a>,
    /// The content, in the plug-in's encoding.
    pub content: &'a [u8],
}

/// A credential as the registration holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential<'a> {
    /// The wallet's id.
    pub id: CredentialId<'a>,
    /// The format.
    pub format: FormatId<'a>,
    /// The format plug-in's view, in its encoding.
    pub view: &'a [u8],
    documents: Vec<Document<'a>>,
    /// What the wallet resolved about it.
    pub facts: Facts<'a>,
}

impl<'a> Credential<'a> {
    /// The credential, each document key once.
    pub fn new(
        id: CredentialId<'a>,
        format: FormatId<'a>,
        view: &'a [u8],
        documents: Vec<Document<'a>>,
        facts: Facts<'a>,
    ) -> Result<Self, RegistrationError> {
        if let Some(twice) = documents.iter().enumerate().find_map(|(k, d)| {
            documents
                .get(..k)
                .and_then(|before| before.iter().find(|e| e.key == d.key))
        }) {
            return Err(RegistrationError::DocumentTwice {
                credential: id.to_string(),
                key: twice.key.to_string(),
            });
        }
        Ok(Self {
            id,
            format,
            view,
            documents,
            facts,
        })
    }

    /// The document of a plug-in.
    #[must_use]
    pub fn document(&self, key: &str) -> Option<&'a [u8]> {
        self.documents
            .iter()
            .find(|document| document.key == *key)
            .map(|document| document.content)
    }

    /// OpenID4VP §6.1.1: no Trusted Authorities Query, or one of the credential's values for one
    /// of the query's types.
    #[must_use]
    pub fn trusted_for(&self, query: &Query<'_>) -> bool {
        query.trusted_authorities.is_empty()
            || query.trusted_authorities.iter().any(|wanted| {
                self.facts.authority(wanted.kind()).is_some_and(|held| {
                    wanted
                        .values()
                        .iter()
                        .any(|value| held.values.contains(value))
                })
            })
    }
}

/// The wallet's credentials, each id once, in the wallet's order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Wallet<'a>(Vec<Credential<'a>>);

impl<'a> Wallet<'a> {
    /// The credentials, each id once.
    pub fn new(credentials: Vec<Credential<'a>>) -> Result<Self, RegistrationError> {
        if let Some(twice) = credentials.iter().enumerate().find_map(|(k, c)| {
            credentials
                .get(..k)
                .and_then(|before| before.iter().find(|d| d.id == c.id))
        }) {
            return Err(RegistrationError::CredentialTwice(twice.id.to_string()));
        }
        Ok(Self(credentials))
    }

    /// The credentials in the wallet's order.
    #[must_use]
    pub fn credentials(&self) -> &[Credential<'a>] {
        &self.0
    }
}
