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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_versions() {
        assert_eq!(parse_version("1.2"), Some((1, 2)));
        assert_eq!(parse_version("0.1"), Some((0, 1)));
    }

    #[test]
    fn refuses_malformed_versions() {
        // No leading zeros on either part (spec errors vector: "0.01").
        assert_eq!(parse_version("0.01"), None);
        assert_eq!(parse_version("01.2"), None);
        assert_eq!(parse_version("1.2.3"), None);
        assert_eq!(parse_version("1."), None);
        assert_eq!(parse_version(".2"), None);
        assert_eq!(parse_version("1"), None);
        assert_eq!(parse_version(" 1.2"), None);
        assert_eq!(parse_version("1e0.2"), None);
    }

    #[test]
    fn negotiates_the_highest_compatible_minor() {
        let supported = ["0.1", "0.2", "1.0"];
        assert_eq!(negotiate_version("0.3", &supported), Some("0.2"));
        assert_eq!(negotiate_version("0.2", &supported), Some("0.2"));
        assert_eq!(negotiate_version("1.0", &supported), Some("1.0"));
        assert_eq!(negotiate_version("2.0", &supported), None);
        assert_eq!(negotiate_version("nonsense", &supported), None);
    }

    #[test]
    fn rejection_splits_invalid_from_unsupported() {
        assert_eq!(
            version_rejection(Some("nope"), &["0.1"]).code,
            ERR_INVALID_PARAMS
        );
        assert_eq!(version_rejection(None, &["0.1"]).code, ERR_INVALID_PARAMS);
        assert_eq!(
            version_rejection(Some("9.9"), &["0.1"]).code,
            ERR_VERSION_NOT_SUPPORTED
        );
    }
}
