//! Protocol versions and their negotiation (core specification §2.2).

use std::fmt;
use std::str::FromStr;

use serde::de::{Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{RpcError, ERR_INVALID_PARAMS, ERR_VERSION_NOT_SUPPORTED};

/// The most digits a part of a version holds.
const MAX_PART_DIGITS: usize = 6;

/// A protocol version, `MAJOR.MINOR` (core §2.2.2).
///
/// Parse one with [`str::parse`], or deserialize it from a JSON string. It
/// displays and serializes as the string it was parsed from. Versions
/// compare as the pair of integers, MAJOR first: `0.10` is later than `0.9`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    major: u32,
    minor: u32,
}

/// The protocol version of this implementation.
pub const VERSION: Version = Version { major: 0, minor: 1 };

/// The protocol versions this crate offers, by default.
///
/// go-wmp holds this as a mutable package variable; the mirror exposes it as
/// a constant, and everything that wants a different set says so in its
/// configuration.
pub const SUPPORTED_VERSIONS: &[Version] = &[VERSION];

/// The error for a string that is not a `MAJOR.MINOR` protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("wmp: not a MAJOR.MINOR protocol version")]
pub struct VersionError;

impl FromStr for Version {
    type Err = VersionError;

    /// Both parts must be plain decimal digits without leading zeros; signs,
    /// spaces, empty parts, missing dots and extra components are rejected
    /// (core §2.2.2). Each part is at most six digits, go-wmp's bound.
    fn from_str(s: &str) -> Result<Self, VersionError> {
        let (major, minor) = s.split_once('.').ok_or(VersionError)?;
        Ok(Self {
            major: parse_part(major)?,
            minor: parse_part(minor)?,
        })
    }
}

fn parse_part(s: &str) -> Result<u32, VersionError> {
    // No leading zeros: "0.01" is malformed (the spec's errors vector).
    if s.is_empty() || s.len() > MAX_PART_DIGITS || (s.len() > 1 && s.starts_with('0')) {
        return Err(VersionError);
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(VersionError);
    }
    s.parse().map_err(|_| VersionError)
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl Serialize for Version {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(VersionVisitor)
    }
}

/// Parses a version out of a string value.
struct VersionVisitor;

impl Visitor<'_> for VersionVisitor {
    type Value = Version;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a MAJOR.MINOR protocol version")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Version, E> {
        v.parse()
            .map_err(|VersionError| E::invalid_value(Unexpected::Str(v), &self))
    }
}

/// Reads the version a message offers in `wmp.version`.
///
/// # Errors
///
/// [`ERR_INVALID_PARAMS`] when the value is not a `MAJOR.MINOR` version:
/// absent (which [`Metadata`](crate::types::Metadata) decodes as empty),
/// empty or malformed (core §2.2.2).
pub fn offered_version(wmp_version: &str) -> Result<Version, RpcError> {
    wmp_version
        .parse()
        .map_err(|VersionError| RpcError::code(ERR_INVALID_PARAMS))
}

/// Selects the version of a session (core §2.2.2): the highest version in
/// `supported` with the MAJOR of `offered` and a MINOR not greater than its
/// MINOR.
///
/// # Errors
///
/// The [`version_not_supported`] error for `supported` when no version
/// qualifies.
pub fn negotiate_version(offered: Version, supported: &[Version]) -> Result<Version, RpcError> {
    supported
        .iter()
        .copied()
        .filter(|version| version.major == offered.major && version.minor <= offered.minor)
        .max()
        .ok_or_else(|| version_not_supported(supported))
}

/// The [`ERR_VERSION_NOT_SUPPORTED`] error, whose `supported_versions` data
/// lists every version of `supported` (core §2.2.2 and §3.8).
pub fn version_not_supported(supported: &[Version]) -> RpcError {
    RpcError::new(
        ERR_VERSION_NOT_SUPPORTED,
        Some(serde_json::json!({
            "supported_versions": supported,
        })),
    )
}
