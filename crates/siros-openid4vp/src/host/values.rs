//! The values the host's modules exchange with the core and the plug-ins: instants and
//! durations, a credential's usability, signatures and presentations.

use serde_json::value::RawValue;

use crate::wallet::Credential;

/// Seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp(pub u64);

/// A duration in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Seconds(pub u64);

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
