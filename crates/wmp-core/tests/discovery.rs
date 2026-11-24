//! Well-known discovery: the domain of each identifier kind, the URL that
//! refuses redirection, and the decoded document.

use wmp_core::discovery::{
    build_well_known_url, discover_config, discover_config_for_identifier, extract_domain,
    parse_did_web, DiscoveryBase, DiscoveryError,
};

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
    let versions: Vec<String> = config
        .supported_versions
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(versions, ["0.1"]);
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

const WK: &str = "/.well-known/wmp-configuration";

/// The rows of the well-known URL table of WMP Core 7.5.1.
#[test]
fn the_well_known_url_inserts_the_segment_before_the_tenant_path() {
    let rows = [
        ("x509:san:dns:example.com", "https://example.com", ""),
        ("https://example.com", "https://example.com", ""),
        ("https://example.com/", "https://example.com", ""),
        (
            "https://example.com/tenant1",
            "https://example.com",
            "/tenant1",
        ),
        (
            "https://example.com:8443/tenants/acme/",
            "https://example.com:8443",
            "/tenants/acme",
        ),
        (
            "x509:san:uri:https://example.com/tenant1",
            "https://example.com",
            "/tenant1",
        ),
        ("did:web:example.com", "https://example.com", ""),
        ("did:web:example.com%3A8443", "https://example.com:8443", ""),
    ];
    for (identifier, origin, tenant) in rows {
        let base = DiscoveryBase::for_identifier(identifier).expect(identifier);
        assert_eq!(
            base.well_known_url(),
            format!("{origin}{WK}{tenant}"),
            "{identifier}"
        );
        assert_eq!(base.url(), format!("{origin}{tenant}"), "{identifier}");
    }
}

#[test]
fn identifiers_without_a_discovery_base() {
    let none = [
        // The did:web method resolves its DID Document.
        "did:web:example.com:tenant1",
        "did:key:z6Mkf5rGMoatrSj1f3JWKc",
        "https://example.com/tenant1?x=1",
        "https://example.com/tenant1?",
        "https://example.com/tenant1#frag",
        "https://user@example.com/tenant1",
        "https://example.com/a/../b",
        "https://example.com/a/./b",
        "https://example.com/a/%2e%2e/b",
        "https://example.com/a/%zz/b",
        "https://example.com\\@evil.example/",
        "x509:san:uri:https://example.com/t?x=1",
        "x509:san:uri:http://example.com/t",
        "x509:san:dns:example.com/path",
        "http://example.com/tenant1",
        "opaque",
    ];
    for identifier in none {
        assert!(
            matches!(
                DiscoveryBase::for_identifier(identifier),
                Err(DiscoveryError::NoDiscoveryBase(_))
            ),
            "{identifier}"
        );
    }
}

fn doc(ws: &str, discovery_base: Option<&str>) -> Vec<u8> {
    let mut doc = serde_json::json!({
        "supported_versions": ["0.1"],
        "endpoints": {"websocket": ws},
    });
    if let Some(base) = discovery_base {
        doc["discovery_base"] = base.into();
    }
    serde_json::to_vec(&doc).expect("encode")
}

#[test]
fn a_tenant_resolves_at_its_own_url_and_never_at_its_hosts() {
    let fetch = |url: &str| match url {
        "https://example.com/.well-known/wmp-configuration" => Ok(doc("wss://root/wmp", None)),
        "https://example.com/.well-known/wmp-configuration/tenants/acme" => Ok(doc(
            "wss://acme/wmp",
            Some("HTTPS://EXAMPLE.com/tenants/acme"),
        )),
        other => Err(format!("404 {other}")),
    };
    for identifier in [
        "https://example.com/tenants/acme",
        "https://example.com/tenants/acme/",
        "x509:san:uri:https://example.com/tenants/acme",
    ] {
        let config = discover_config_for_identifier(fetch, identifier).expect(identifier);
        assert_eq!(
            config.endpoints["websocket"], "wss://acme/wmp",
            "{identifier}"
        );
    }
    let root = discover_config_for_identifier(fetch, "x509:san:dns:example.com").expect("root");
    assert_eq!(root.endpoints["websocket"], "wss://root/wmp");

    // A tenant without a configuration of its own does not get the host's.
    assert!(matches!(
        discover_config_for_identifier(fetch, "https://example.com/tenants/other"),
        Err(DiscoveryError::Fetch(_))
    ));
}

/// A catch-all server answers every well-known path with one document.
#[test]
fn a_document_for_another_base_is_refused() {
    let tenant = "https://example.com/tenant1";
    for (name, base) in [
        ("absent", None),
        ("empty", Some("")),
        ("the host's", Some("https://example.com")),
        ("another tenant's", Some("https://example.com/tenant2")),
        ("another host's", Some("https://evil.example/tenant1")),
        ("another port's", Some("https://example.com:8443/tenant1")),
        ("path case", Some("https://example.com/TENANT1")),
    ] {
        let got = discover_config_for_identifier(|_| Ok(doc("wss://x/wmp", base)), tenant);
        assert!(
            matches!(got, Err(DiscoveryError::BaseMismatch { .. })),
            "{name}"
        );
    }

    // A whole host may leave the base out, but not name another.
    for base in [
        None,
        Some("https://example.com"),
        Some("https://example.com/"),
    ] {
        discover_config(|_| Ok(doc("wss://x/wmp", base)), "example.com").expect("host");
    }
    assert!(matches!(
        discover_config(
            |_| Ok(doc("wss://x/wmp", Some("https://example.com/tenant1"))),
            "example.com"
        ),
        Err(DiscoveryError::BaseMismatch { .. })
    ));
}
