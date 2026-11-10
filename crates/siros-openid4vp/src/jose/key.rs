//! Public keys as RFC 7517 writes them: the key a prefix binds and a signature verifies under, and
//! the wallet's ephemeral key. The core holds no curve arithmetic: the verifying and decrypting
//! modules check a key's fit to their algorithm, a point off its curve included.

use siros_explain::Explain;

use crate::json::{Node, Object};

/// A public key as RFC 7517 writes it: a JSON object with unique member names, `kty` a string,
/// and no private member (RFC 7518 §6.2.2, §6.3.2, §6.4; RFC 8037 §2's `d`). Only
/// [`PublicJwk::parse`] makes one.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicJwk(Object<'static>);

/// A JWK that is no public key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum NotPublicJwk {
    /// No JSON object.
    #[error("the JWK is no JSON object")]
    #[explain(id = "jose.object")]
    Object,
    /// `kty` absent or no string.
    #[error("the JWK holds no kty")]
    #[explain(id = "jose.key_type")]
    KeyType,
    /// A private member (RFC 7518 §6.2.2, §6.3.2, §6.4).
    #[error("the JWK holds the private member {member}")]
    #[explain(id = "jose.private")]
    Private {
        /// The member's name.
        member: String,
    },
}

/// The members RFC 7518 §6.2.2, §6.3.2 and §6.4 and RFC 8037 §2 name for private keys.
const PRIVATE: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

impl PublicJwk {
    /// The key, refused per [`NotPublicJwk`].
    ///
    /// # Errors
    ///
    /// The JWK is no object, holds no `kty`, or holds a private member.
    pub fn parse(jwk: Node<'_>) -> Result<Self, NotPublicJwk> {
        let Node::Object(object) = jwk else {
            return Err(NotPublicJwk::Object);
        };
        if object.get("kty").and_then(Node::as_str).is_none() {
            return Err(NotPublicJwk::KeyType);
        }
        if let Some(private) = PRIVATE.into_iter().find(|name| object.get(name).is_some()) {
            return Err(NotPublicJwk::Private {
                member: private.to_owned(),
            });
        }
        Ok(Self(object.into_owned()))
    }

    /// A member as the JWK writes it.
    #[must_use]
    pub fn member(&self, name: &str) -> Option<&Node<'static>> {
        self.0.get(name)
    }

    /// The JWK's members.
    #[must_use]
    pub const fn object(&self) -> &Object<'static> {
        &self.0
    }
}

/// The key a prefix binds and a signature verifies under. `Haip::verify` checks that it fits the
/// signature's `alg`, a point off its curve included.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationKey(PublicJwk);

impl VerificationKey {
    /// The key.
    #[must_use]
    pub const fn of(jwk: PublicJwk) -> Self {
        Self(jwk)
    }

    /// The JWK.
    #[must_use]
    pub const fn jwk(&self) -> &PublicJwk {
        &self.0
    }
}
