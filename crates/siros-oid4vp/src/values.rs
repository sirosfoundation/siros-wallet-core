//! The values a request carries and intake's effects name.

use std::fmt;

use serde::{Deserialize, Serialize};
use siros_codec::base64url::{self, Base64Url};

/// The origin the platform attests for a DC API request (Appendix A.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Origin(String);

impl Origin {
    /// The origin `text`, as the platform states it.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(text.to_owned())
    }

    /// The origin.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The `wallet_nonce` of a `request_uri_method=post` request (Section 5.10): the base64url of
/// 16 random bytes, which the Request Object echoes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WalletNonce(Base64Url);

impl WalletNonce {
    /// The nonce of `random`, 128 bits from the caller's CSPRNG.
    pub(crate) fn new(random: [u8; 16]) -> Self {
        Self(base64url::encode(&random))
    }

    /// The nonce.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl TryFrom<String> for WalletNonce {
    type Error = siros_codec::Base64Error;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Base64Url::parse(&text).map(Self)
    }
}

impl From<WalletNonce> for String {
    fn from(nonce: WalletNonce) -> Self {
        nonce.0.into()
    }
}

/// The `kid` Header Parameter or JWK member: the identifier of a key (RFC 7515, Section 4.1.4;
/// RFC 7517, Section 4.5).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Kid(String);

impl Kid {
    /// The identifier `text`.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(text.to_owned())
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The `iss` of a Verifier Attestation JWT (Section 12): the name the host evaluates trust in.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttestationIssuer(String);

impl AttestationIssuer {
    pub(crate) fn new(text: String) -> Self {
        Self(text)
    }

    /// The issuer.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The `trust_chain` Header Parameter of an `openid_federation` request: the Entity Statements
/// of the Trust Chain, each a JWS (OpenID Federation 1.0, Section 4.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustChain(Vec<String>);

impl TrustChain {
    pub(crate) fn new(statements: Vec<String>) -> Self {
        Self(statements)
    }

    /// The Entity Statements, in the chain's order.
    #[must_use]
    pub fn statements(&self) -> &[String] {
        &self.0
    }
}
