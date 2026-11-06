//! Protocol version parsing, negotiation and rejection (core §2.2).

use wmp_core::error::{ERR_INVALID_PARAMS, ERR_VERSION_NOT_SUPPORTED};
use wmp_core::types::Metadata;
use wmp_core::version::{negotiate_version, offered_version, Version};

/// A supported list, each entry parsed as a configuration parses it.
fn versions(list: &[&str]) -> Vec<Version> {
    list.iter()
        .map(|version| {
            version
                .parse()
                .unwrap_or_else(|_| panic!("{version:?} is a version"))
        })
        .collect()
}

/// The version negotiated for `offered` against `supported`, in its wire
/// form.
fn negotiated(offered: &str, supported: &[&str]) -> Option<String> {
    let offered = offered_version(offered).ok()?;
    let selected = negotiate_version(offered, &versions(supported)).ok()?;
    Some(selected.to_string())
}

/// A well-formed offer is read as its MAJOR and MINOR: it accepts a lower
/// MINOR of its MAJOR and refuses a higher MINOR or another MAJOR.
#[test]
fn parses_valid_versions() {
    assert_eq!(negotiated("1.2", &["1.1"]).as_deref(), Some("1.1"));
    assert_eq!(negotiated("1.2", &["1.3"]), None);
    assert_eq!(negotiated("1.2", &["0.2"]), None);
    assert_eq!(negotiated("1.2", &["2.2"]), None);
    assert_eq!(negotiated("0.1", &["0.0"]).as_deref(), Some("0.0"));
    assert_eq!(negotiated("0.1", &["0.2"]), None);
    assert_eq!(negotiated("0.1", &["1.1"]), None);
}

/// A malformed offer is invalid params; a well-formed one is unsupported.
#[test]
fn refuses_malformed_versions() {
    // No leading zeros on either part (spec errors vector: "0.01").
    for malformed in ["0.01", "01.2", "1.2.3", "1.", ".2", "1", " 1.2", "1e0.2"] {
        assert_eq!(
            offered_version(malformed).err().map(|err| err.code),
            Some(ERR_INVALID_PARAMS),
            "{malformed:?}"
        );
    }
}

#[test]
fn negotiates_the_highest_compatible_minor() {
    let supported = ["0.1", "0.2", "1.0"];
    assert_eq!(negotiated("0.3", &supported).as_deref(), Some("0.2"));
    assert_eq!(negotiated("0.2", &supported).as_deref(), Some("0.2"));
    assert_eq!(negotiated("1.0", &supported).as_deref(), Some("1.0"));
    assert_eq!(negotiated("2.0", &supported), None);
    assert_eq!(negotiated("nonsense", &supported), None);
}

#[test]
fn rejection_splits_invalid_from_unsupported() {
    assert_eq!(
        offered_version("nope").err().map(|err| err.code),
        Some(ERR_INVALID_PARAMS)
    );
    // An envelope without a version decodes it as empty.
    let absent: Metadata = serde_json::from_str("{}").expect("an envelope");
    assert_eq!(
        offered_version(&absent.version).err().map(|err| err.code),
        Some(ERR_INVALID_PARAMS)
    );
    let offered = offered_version("9.9").expect("a version");
    assert_eq!(
        negotiate_version(offered, &versions(&["0.1"]))
            .err()
            .map(|err| err.code),
        Some(ERR_VERSION_NOT_SUPPORTED)
    );
}
