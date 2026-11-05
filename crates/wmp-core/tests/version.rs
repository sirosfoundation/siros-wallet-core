//! Protocol version parsing, negotiation and rejection (core §2.2).

use wmp_core::error::{ERR_INVALID_PARAMS, ERR_VERSION_NOT_SUPPORTED};
use wmp_core::version::{negotiate_version, version_rejection};

/// A well-formed offer is read as its MAJOR and MINOR: it accepts a lower
/// MINOR of its MAJOR and refuses a higher MINOR or another MAJOR.
#[test]
fn parses_valid_versions() {
    assert_eq!(negotiate_version("1.2", &["1.1"]), Some("1.1"));
    assert_eq!(negotiate_version("1.2", &["1.3"]), None);
    assert_eq!(negotiate_version("1.2", &["0.2"]), None);
    assert_eq!(negotiate_version("1.2", &["2.2"]), None);
    assert_eq!(negotiate_version("0.1", &["0.0"]), Some("0.0"));
    assert_eq!(negotiate_version("0.1", &["0.2"]), None);
    assert_eq!(negotiate_version("0.1", &["1.1"]), None);
}

/// A malformed offer is invalid params; a well-formed one is unsupported.
#[test]
fn refuses_malformed_versions() {
    // No leading zeros on either part (spec errors vector: "0.01").
    for malformed in ["0.01", "01.2", "1.2.3", "1.", ".2", "1", " 1.2", "1e0.2"] {
        assert_eq!(
            version_rejection(Some(malformed), &["0.1"]).code,
            ERR_INVALID_PARAMS,
            "{malformed:?}"
        );
    }
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
