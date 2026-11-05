//! Well-known discovery: the domain of each identifier kind, the URL that
//! refuses redirection, and the decoded document.

use wmp_core::discovery::{build_well_known_url, discover_config, extract_domain, parse_did_web};

#[test]
fn domains_come_from_every_identifier_kind() {
    assert_eq!(extract_domain("did:web:example.com"), "example.com");
    assert_eq!(
        extract_domain("did:web:example.com:users:alice"),
        "example.com"
    );
    assert_eq!(extract_domain("https://example.com/path?q"), "example.com");
    assert_eq!(extract_domain("x509:san:dns:example.com"), "example.com");
    assert_eq!(
        extract_domain("x509:san:uri:https://example.com/wmp"),
        "example.com"
    );
    assert_eq!(extract_domain("did:key:z6Mk"), "");
}

#[test]
fn url_building_refuses_redirection() {
    assert!(matches!(
        build_well_known_url("example.com").as_deref(),
        Ok("https://example.com/.well-known/wmp-configuration")
    ));
    assert!(build_well_known_url("").is_err());
    assert!(build_well_known_url("example.com/admin").is_err());
    assert!(build_well_known_url("user@example.com").is_err());
    assert!(build_well_known_url("example.com#x").is_err());
}

#[test]
fn discovery_decodes_a_document() {
    let doc = br#"{"supported_versions":["0.1"],"endpoints":{"wss":"wss://example.com/wmp"}}"#;
    let config = discover_config(
        |url| {
            assert_eq!(url, "https://example.com/.well-known/wmp-configuration");
            Ok(doc.to_vec())
        },
        "example.com",
    )
    .expect("discover");
    assert_eq!(config.supported_versions, ["0.1"]);
    assert!(config.endpoints.contains_key("wss"));
}

#[test]
fn did_web_sub_paths_are_parsed_but_not_followed() {
    assert_eq!(
        parse_did_web("did:web:example.com:users:alice"),
        Some(("example.com".to_owned(), "users/alice".to_owned()))
    );
    assert_eq!(
        parse_did_web("did:web:example.com%3A8080"),
        Some(("example.com:8080".to_owned(), String::new()))
    );
    assert_eq!(parse_did_web("did:web:.example.com"), None);
    assert_eq!(parse_did_web("did:key:z"), None);
}
