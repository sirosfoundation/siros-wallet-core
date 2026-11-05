//! Protocol version parsing and negotiation (core specification §2.2).

use crate::error::{RpcError, ERR_INVALID_PARAMS, ERR_VERSION_NOT_SUPPORTED};

/// Parses a `MAJOR.MINOR` protocol version.
///
/// Both parts must be plain decimal digits without leading zeros; signs,
/// spaces, empty parts, missing dots and extra components are rejected. Each
/// part is at most six digits.
fn parse_version(v: &str) -> Option<(u64, u64)> {
    let (major, minor) = v.split_once('.')?;
    Some((parse_part(major)?, parse_part(minor)?))
}

fn parse_part(s: &str) -> Option<u64> {
    // No leading zeros: "0.01" is malformed (the spec's errors vector).
    if s.is_empty() || s.len() > 6 || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Negotiates the protocol version (core §2.2.2): the highest version in
/// `supported` with the same MAJOR as `offered` and a MINOR not greater than
/// `offered`'s. The returned string is the entry from `supported`, unmodified.
///
/// Returns `None` when `offered` is not a valid `MAJOR.MINOR` version or no
/// supported version is compatible; the caller then rejects the request with
/// the error from [`version_rejection`]. Unparseable entries in `supported`
/// are ignored.
pub fn negotiate_version<'a>(offered: &'a str, supported: &'a [&'a str]) -> Option<&'a str> {
    let (off_major, off_minor) = parse_version(offered)?;
    let mut best: Option<(u64, &str)> = None;
    for s in supported {
        let (major, minor) = parse_version(s)?;
        if major != off_major || minor > off_minor {
            continue;
        }
        if best.is_none_or(|(best_minor, _)| minor > best_minor) {
            best = Some((minor, s));
        }
    }
    best.map(|(_, s)| s)
}

/// The error for an offered version that [`negotiate_version`] could not
/// match: [`ERR_INVALID_PARAMS`] when the offered value is not a valid
/// `MAJOR.MINOR` string (including an absent one), else
/// [`ERR_VERSION_NOT_SUPPORTED`] carrying `supported_versions` (core §2.2.2
/// and §3.8).
pub fn version_rejection(offered: Option<&str>, supported: &[&str]) -> RpcError {
    match offered.and_then(parse_version) {
        None => RpcError::code(ERR_INVALID_PARAMS),
        Some(_) => RpcError::new(
            ERR_VERSION_NOT_SUPPORTED,
            Some(serde_json::json!({
                "supported_versions": supported,
            })),
        ),
    }
}
