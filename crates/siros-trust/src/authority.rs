//! The authorities a Credential Query names in `trusted_authorities` (OpenID4VP 1.0, Section
//! 6.1.1), read for the admission rule (TR3).

use siros_codec::{base64url, Base64Error};
use siros_dcql::{AuthorityType, AuthorityValue, CredentialQuery, QueryId, TrustedAuthorities};

/// The keyIdentifier of an AuthorityKeyIdentifier extension (RFC 5280, Section 4.2.1.1): the
/// bytes by which a certificate names its signer's key. Never empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyIdentifier(Vec<u8>);

/// Why bytes are no keyIdentifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum KeyIdentifierError {
    /// The keyIdentifier is empty.
    Empty,
}

impl KeyIdentifierError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Empty => "key_identifier_empty",
        }
    }
}

impl KeyIdentifier {
    /// The keyIdentifier `bytes`, as a certificate or a registration projection holds them.
    ///
    /// # Errors
    ///
    /// [`KeyIdentifierError::Empty`] for no bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, KeyIdentifierError> {
        if bytes.is_empty() {
            return Err(KeyIdentifierError::Empty);
        }
        Ok(Self(bytes.to_vec()))
    }

    /// The keyIdentifier an `aki` value carries: its base64url decoding (Section 6.1.1.1).
    ///
    /// # Errors
    ///
    /// [`AkiError`]: a value that is not base64url without padding, or that encodes no byte.
    pub fn from_aki(value: &AuthorityValue) -> Result<Self, AkiError> {
        let bytes = base64url::decode(value.as_str()).map_err(AkiError::Base64url)?;
        Self::new(&bytes).map_err(AkiError::KeyIdentifier)
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The `type` of a trust store entry: an authority whose certificates the store holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreType {
    /// `etsi_tl`: an ETSI TS 119 612 Trusted List.
    EtsiTl,
    /// `openid_federation`: an OpenID Federation Entity, usually a Trust Anchor.
    OpenidFederation,
}

/// A `trusted_authorities` `type` (OpenID4VP 1.0, Section 6.1.1) that TR3 reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum KnownAuthorityType {
    /// `aki`: the keyIdentifier of a certificate of the issuer's chain.
    Aki,
    /// An authority whose certificates a trust store entry holds.
    Store(StoreType),
}

impl KnownAuthorityType {
    /// The known type `kind` names; `None` for another type.
    pub(crate) fn of(kind: &AuthorityType) -> Option<Self> {
        match kind.as_str() {
            "aki" => Some(Self::Aki),
            other => StoreType::named(other).map(Self::Store),
        }
    }
}

impl StoreType {
    /// The `type` as OpenID4VP 1.0, Section 6.1.1 writes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EtsiTl => "etsi_tl",
            Self::OpenidFederation => "openid_federation",
        }
    }

    /// The store type the `type` `name` names.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        [Self::EtsiTl, Self::OpenidFederation]
            .into_iter()
            .find(|kind| kind.as_str() == name)
    }
}

/// An authority a trust store entry can hold: its type and its value, as a Verifier sends the
/// value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoreAuthority {
    kind: StoreType,
    value: AuthorityValue,
}

impl StoreAuthority {
    /// The authority of type `kind` and value `value`.
    #[must_use]
    pub fn new(kind: StoreType, value: AuthorityValue) -> Self {
        Self { kind, value }
    }

    /// The type.
    #[must_use]
    pub fn kind(&self) -> StoreType {
        self.kind
    }

    /// The value.
    #[must_use]
    pub fn value(&self) -> &AuthorityValue {
        &self.value
    }
}

/// One value of a query's `trusted_authorities`, read by its entry's `type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authority {
    /// An `aki` value: the keyIdentifier it encodes.
    KeyIdentifier(KeyIdentifier),
    /// An `etsi_tl` or `openid_federation` value.
    Store(StoreAuthority),
    /// A value of another type, which TR3 refuses for every issuer.
    Other(AuthorityType),
}

/// What a Credential Query names in `trusted_authorities`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Named {
    /// The query has no `trusted_authorities`: every issuer is admitted.
    Nothing,
    /// `trusted_authorities` as DCQL parsed it, and the authorities of its values, at least
    /// one, in the Verifier's order.
    Authorities {
        sent: TrustedAuthorities,
        read: Vec<Authority>,
    },
}

/// The authorities a Credential Query names, read for the admission rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryAuthorities {
    query: QueryId,
    named: Named,
}

/// Why an `aki` value encodes no keyIdentifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum AkiError {
    /// The value is not base64url without padding.
    Base64url(#[source] Base64Error),
    /// The bytes are no keyIdentifier.
    KeyIdentifier(#[source] KeyIdentifierError),
}

impl AkiError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Base64url(_) => "aki_not_base64url",
            Self::KeyIdentifier(error) => error.code(),
        }
    }
}

/// Why a query's `trusted_authorities` cannot be read. The request is invalid
/// (`invalid_request`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum AuthorityError {
    /// An `aki` value encodes no keyIdentifier.
    Aki {
        /// The value.
        value: AuthorityValue,
        /// Why.
        #[source]
        error: AkiError,
    },
}

impl AuthorityError {
    /// A stable identifier: the code of the value's error.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Aki { error, .. } => error.code(),
        }
    }
}

impl QueryAuthorities {
    /// The authorities `query` names: each value of its `trusted_authorities`, in their order.
    ///
    /// # Errors
    ///
    /// [`AuthorityError::Aki`] for the first `aki` value that encodes no keyIdentifier.
    pub fn of(query: &CredentialQuery) -> Result<Self, AuthorityError> {
        let named = match query.trusted_authorities() {
            None => Named::Nothing,
            Some(authorities) => Named::Authorities {
                read: authorities
                    .entries()
                    .iter()
                    .flat_map(|entry| {
                        entry
                            .values()
                            .iter()
                            .map(|value| Authority::read(entry.kind(), value))
                    })
                    .collect::<Result<_, _>>()?,
                sent: authorities.clone(),
            },
        };
        Ok(Self {
            query: query.id().clone(),
            named,
        })
    }

    /// The query's `id`.
    #[must_use]
    pub fn query(&self) -> &QueryId {
        &self.query
    }

    /// The authorities, in the Verifier's order; `None` when the query names none and admits
    /// every issuer.
    #[must_use]
    pub fn authorities(&self) -> Option<&[Authority]> {
        match &self.named {
            Named::Nothing => None,
            Named::Authorities { read, .. } => Some(read),
        }
    }

    /// Whether these are the authorities of `query`: its `id` and its `trusted_authorities`.
    #[must_use]
    pub fn are_those_of(&self, query: &CredentialQuery) -> bool {
        let sent = match &self.named {
            Named::Nothing => None,
            Named::Authorities { sent, .. } => Some(sent),
        };
        self.query == *query.id() && sent == query.trusted_authorities()
    }
}

impl Authority {
    /// The authority of the value `value` of an entry of type `kind`.
    fn read(kind: &AuthorityType, value: &AuthorityValue) -> Result<Self, AuthorityError> {
        Ok(match KnownAuthorityType::of(kind) {
            Some(KnownAuthorityType::Aki) => KeyIdentifier::from_aki(value)
                .map(Self::KeyIdentifier)
                .map_err(|error| AuthorityError::Aki {
                    value: value.clone(),
                    error,
                })?,
            Some(KnownAuthorityType::Store(store)) => {
                Self::Store(StoreAuthority::new(store, value.clone()))
            }
            None => Self::Other(kind.clone()),
        })
    }
}
