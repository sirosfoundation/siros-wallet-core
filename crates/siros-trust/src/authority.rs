//! The authorities a chain or a trust store entry stands for: the keyIdentifier of an `aki` value
//! and the `etsi_tl` and `openid_federation` values a store holds (OpenID4VP 1.0, Section 6.1.1).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::ids::{AuthorityType, AuthorityValue};

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
    /// The keyIdentifier `bytes`, as a certificate holds them.
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

    /// The `aki` value that names this key: its base64url encoding, without padding (Section
    /// 6.1.1.1).
    #[must_use]
    pub fn aki(&self) -> AuthorityValue {
        AuthorityValue::of(URL_SAFE_NO_PAD.encode(&self.0))
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

    /// The Trusted Authorities type of this store type.
    #[must_use]
    pub fn authority_type(self) -> AuthorityType {
        AuthorityType::of(self.as_str())
    }
}

/// An authority a trust store entry holds: its type and its value, as a Verifier sends the value.
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
