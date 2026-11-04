//! The values the host's modules exchange with the core and the plug-ins: instants and
//! durations, fresh identifiers, a credential's usability, signatures and presentations.

use std::fmt;

use serde_json::value::RawValue;
use siros_explain::Explain;
use uuid::{Builder, Uuid, Variant, Version};

use crate::wallet::Credential;

/// Seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp(pub u64);

/// A duration in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Seconds(pub u64);

/// A random UUID (RFC 9562 §5.4), written as its lowercase hyphenated text (RFC 9562 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RandomId(Uuid);

/// A text that is no version 4 UUID in lowercase hyphenated form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.random_id")]
pub enum NotRandomId {
    /// No UUID text (RFC 9562 §4).
    #[error("{text:?} is no UUID: {cause}")]
    Uuid {
        /// The text.
        text: String,
        /// uuid's reason.
        #[source]
        #[explain(skip)]
        cause: uuid::Error,
    },
    /// A UUID of another version or variant.
    #[error("{0:?} is no version 4 UUID of the RFC 9562 variant")]
    Version(#[explain(name = "text")] String),
    /// A UUID written in another form: braces, a URN, no hyphens, or uppercase digits.
    #[error("{0:?} is no UUID's lowercase hyphenated text")]
    Text(#[explain(name = "text")] String),
}

impl RandomId {
    /// The UUID of 16 random bytes, its version and variant bits set (RFC 9562 §5.4).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Builder::from_random_bytes(bytes).into_uuid())
    }

    /// Parses `xxxxxxxx-xxxx-4xxx-Vxxx-xxxxxxxxxxxx` in lowercase, V one of 8, 9, a, b.
    ///
    /// # Errors
    ///
    /// The text is no UUID, a UUID of another version or variant, or a UUID in another form.
    pub fn parse(text: &str) -> Result<Self, NotRandomId> {
        let uuid = Uuid::try_parse(text).map_err(|cause| NotRandomId::Uuid {
            text: text.to_owned(),
            cause,
        })?;
        if uuid.get_version() != Some(Version::Random) || uuid.get_variant() != Variant::RFC4122 {
            return Err(NotRandomId::Version(text.to_owned()));
        }
        let mut buffer = Uuid::encode_buffer();
        if uuid.hyphenated().encode_lower(&mut buffer) != text {
            return Err(NotRandomId::Text(text.to_owned()));
        }
        Ok(Self(uuid))
    }
}

impl fmt::Display for RandomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.hyphenated(), f)
    }
}

/// The platform's verdict that a credential can still be presented (validity, status), which a
/// presentation requires.
#[derive(Debug, Clone, Copy)]
pub struct Usable<'c>(&'c Credential<'c>);

impl<'c> Usable<'c> {
    /// The verdict for a credential the platform checked now.
    #[must_use]
    pub const fn checked(credential: &'c Credential<'c>) -> Self {
        Self(credential)
    }

    /// The credential.
    #[must_use]
    pub const fn credential(self) -> &'c Credential<'c> {
        self.0
    }
}

/// A signature's bytes as the key made them: R and S for ECDSA (RFC 7518 §3.4, RFC 9053 §2.1).
/// The format places them and reads none of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// The bytes the key made.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// A presentation as a JSON value: what `vp_token` holds for one credential.
#[derive(Debug, Clone)]
pub struct Presentation(pub Box<RawValue>);
