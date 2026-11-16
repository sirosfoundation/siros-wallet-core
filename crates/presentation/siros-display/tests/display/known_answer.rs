//! A card and claim labels of the SD-JWT VC example of OpenID4VCI 1.0.
//!
//! SOURCE: OpenID for Verifiable Credential Issuance 1.0 (Final, 16 September 2025),
//! https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html, Section 12.2.4:
//! the non-normative Credential Issuer Metadata of `SD_JWT_VC_example_in_OpenID4VCI`, copied
//! verbatim into `credential_configurations_supported`. `credential_issuer` and
//! `credential_endpoint` complete the document. The credential holding the claims is written
//! here.

use serde_json::{json, Value};
use siros_codec::base64url;
use siros_credential::Credential;
use siros_dcql::{ClaimPath, PathComponent};
use siros_display::{
    CardText, CardWording, DisplayCache, DisplayValue, IssuerMetadata, IssuerTemplate, Locale,
    TemplateError, TextError, TEMPLATE_MAX,
};
use siros_wallet_state::WalletState;

const CONFIGURATIONS: &str = r##"{
    "SD_JWT_VC_example_in_OpenID4VCI": {
      "format": "dc+sd-jwt",
      "scope": "SD_JWT_VC_example_in_OpenID4VCI",
      "cryptographic_binding_methods_supported": [
        "jwk"
      ],
      "credential_signing_alg_values_supported": [
        "ES256"
      ],
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": [
            "ES256"
          ],
          "key_attestations_required": {
            "key_storage": [ "iso_18045_moderate" ],
            "user_authentication": [ "iso_18045_moderate" ]
          }
        }
      },
      "vct": "SD_JWT_VC_example_in_OpenID4VCI",
      "credential_metadata": {
        "display": [
          {
            "name": "IdentityCredential",
            "logo": {
              "uri": "https://university.example.edu/public/logo.png",
              "alt_text": "a square logo of a university"
            },
            "locale": "en-US",
            "background_color": "#12107c",
            "text_color": "#FFFFFF"
          }
        ],
        "claims": [
          {
            "path": ["given_name"],
            "display": [
              {
                "name": "Given Name",
                "locale": "en-US"
              },
              {
                "name": "Vorname",
                "locale": "de-DE"
              }
            ]
          },
          {
            "path": ["family_name"],
            "display": [
              {
                "name": "Surname",
                "locale": "en-US"
              },
              {
                "name": "Nachname",
                "locale": "de-DE"
              }
            ]
          },
          {"path": ["email"]},
          {"path": ["phone_number"]},
          {
            "path": ["address"],
            "display": [
              {
                "name": "Place of residence",
                "locale": "en-US"
              },
              {
                "name": "Wohnsitz",
                "locale": "de-DE"
              }
            ]
          },
          {"path": ["address", "street_address"]},
          {"path": ["address", "locality"]},
          {"path": ["address", "region"]},
          {"path": ["address", "country"]},
          {"path": ["birthdate"]},
          {"path": ["is_over_18"]},
          {"path": ["is_over_21"]},
          {"path": ["is_over_65"]}
        ]
      }
    }
  }"##;

const ISSUER: &str = "https://issuer.example";
const CONFIGURATION: &str = "SD_JWT_VC_example_in_OpenID4VCI";

/// The SD-JWT VC of the configuration, every claim permanently disclosed.
fn credential() -> Credential {
    let payload = json!({
        "vct": CONFIGURATION,
        "given_name": "Erika",
        "family_name": "Mustermann",
        "email": "erika@example.com",
        "address": {"street_address": "Heidestraße 17", "locality": "Köln"}
    });
    let sd_jwt = format!(
        "{}.{}.{}~",
        base64url::encode(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#).into_string(),
        base64url::encode(payload.to_string().as_bytes()).into_string(),
        base64url::encode(&[7; 64]).into_string(),
    );
    let state = json!({
        "schemaVersion": 4,
        "credentials": [{
            "credentialId": 1, "format": "dc+sd-jwt", "data": sd_jwt, "kid": "key-1",
            "instanceId": 0, "batchId": 1, "credentialIssuerIdentifier": ISSUER,
            "credentialConfigurationId": CONFIGURATION
        }],
        "keypairs": [], "presentations": [],
        "settings": {"openidRefreshTokenMaxAgeInSeconds": "0"},
        "credentialIssuanceSessions": []
    });
    let state = WalletState::parse(&state.to_string()).unwrap();
    Credential::parse(&state.credentials()[0]).unwrap()
}

fn pointer(keys: &[&str]) -> ClaimPath {
    ClaimPath::new(
        keys.iter()
            .map(|k| PathComponent::Key((*k).into()))
            .collect(),
    )
    .unwrap()
}

#[test]
fn the_card_and_the_labels_of_the_example() {
    let configurations: Value = serde_json::from_str(CONFIGURATIONS).unwrap();
    let issuer_metadata = json!({
        "credential_issuer": ISSUER,
        "credential_endpoint": "https://issuer.example/credential",
        "credential_configurations_supported": configurations
    });
    let metadata = IssuerMetadata::merge(&issuer_metadata, CONFIGURATION, None).unwrap();
    let cache = DisplayCache::new(vec![metadata], vec![]).unwrap();
    let credential = credential();
    let pointers = [
        pointer(&["given_name"]),
        pointer(&["family_name"]),
        pointer(&["email"]),
        pointer(&["address"]),
    ];

    // (language, given_name, family_name, address). RFC 4647 Lookup finds no `de` tag for
    // "de", whose labels fall back to the claim names.
    let table = [
        ("en-US", "Given Name", "Surname", "Place of residence"),
        ("de-DE", "Vorname", "Nachname", "Wohnsitz"),
        ("de", "given_name", "family_name", "address"),
        ("fr-FR", "given_name", "family_name", "address"),
    ];
    for (language, given_name, family_name, address) in table {
        let language = Locale::parse(language).unwrap();
        let card = cache.card(&credential, &language, &wording(None));
        // The Credential Issuer's display names no issuer: the issuer line is the host's.
        assert_eq!(card.issuer().as_str(), "Unknown issuer", "{language}");
        // The display has one entry, en-US: another language has no entry, and the title is
        // the host's.
        if language.as_str() == "en-US" {
            assert_eq!(card.title().as_str(), "IdentityCredential");
            let logo = card.logo().unwrap();
            assert_eq!(
                logo.uri().as_str(),
                "https://university.example.edu/public/logo.png"
            );
            assert_eq!(
                logo.alt_text().map(|a| a.as_str()),
                Some("a square logo of a university")
            );
            let rgba = |c: siros_display::Colour| (c.red(), c.green(), c.blue(), c.alpha());
            assert_eq!(card.background().map(rgba), Some((0x12, 0x10, 0x7c, 0xff)));
            assert_eq!(card.text().map(rgba), Some((0xff, 0xff, 0xff, 0xff)));
        } else {
            assert_eq!(card.title().as_str(), "Credential", "{language}");
            assert!(card.logo().is_none(), "{language}");
        }

        let rows = cache.claim_rows(&credential, &pointers, &language).unwrap();
        let labels: Vec<&str> = rows.iter().map(|row| row.label().as_str()).collect();
        // `email` has no display: its label is its name.
        assert_eq!(
            labels,
            [given_name, family_name, "email", address],
            "{language}"
        );
        let DisplayValue::Group(members) = rows[3].value() else {
            panic!("{language}: address is no group");
        };
        let members: Vec<&str> = members.iter().map(|row| row.label().as_str()).collect();
        assert_eq!(members, ["locality", "street_address"], "{language}");
    }
}

/// Type Metadata comes first, and the configuration's `credential_metadata` serves a language
/// the Type Metadata has no entry for (D3; OpenID4VCI 1.0, Section 12.2.4).
#[test]
fn the_configuration_serves_a_language_the_type_metadata_lacks() {
    let configurations: Value = serde_json::from_str(CONFIGURATIONS).unwrap();
    let issuer_metadata = json!({
        "credential_issuer": ISSUER,
        "credential_endpoint": "https://issuer.example/credential",
        "credential_configurations_supported": configurations
    });
    let metadata = IssuerMetadata::merge(&issuer_metadata, CONFIGURATION, None).unwrap();
    let type_metadata = siros_display::TypeMetadata::parse(&json!({
        "vct": CONFIGURATION,
        "display": [{"locale": "fr", "name": "Identité"}],
        "claims": [{"path": ["given_name"], "display": [{"locale": "fr", "label": "Prénom"}]}]
    }))
    .unwrap();
    let cache = DisplayCache::new(vec![metadata], vec![type_metadata]).unwrap();
    let credential = credential();
    for (language, title, label) in [
        ("fr", "Identité", "Prénom"),
        ("en-US", "IdentityCredential", "Given Name"),
    ] {
        let language = Locale::parse(language).unwrap();
        let card = cache.card(&credential, &language, &wording(None));
        assert_eq!(card.title().as_str(), title, "{language}");
        let rows = cache
            .claim_rows(&credential, &[pointer(&["given_name"])], &language)
            .unwrap();
        assert_eq!(rows[0].label().as_str(), label, "{language}");
    }
}

/// The host's card wording, its issuer line `template`.
fn wording(template: Option<&str>) -> CardWording {
    CardWording {
        title: CardText::new("Credential").unwrap(),
        issuer: CardText::new("Unknown issuer").unwrap(),
        issuer_template: template.map(|template| IssuerTemplate::parse(template).unwrap()),
    }
}

/// A named issuer's line is the name in the host's template; an issuer without a name has the
/// host's issuer line (the owner's wallet's `displaySubtitle` and `displaySubtitleFallback`).
#[test]
fn the_issuer_line_is_the_name_in_the_hosts_template() {
    let configurations: Value = serde_json::from_str(CONFIGURATIONS).unwrap();
    let language = Locale::parse("en-US").unwrap();
    let card = |display: Option<Value>, template: Option<&str>| {
        let mut issuer_metadata = json!({
            "credential_issuer": ISSUER,
            "credential_endpoint": "https://issuer.example/credential",
            "credential_configurations_supported": configurations
        });
        if let Some(display) = display {
            issuer_metadata["display"] = display;
        }
        let metadata = IssuerMetadata::merge(&issuer_metadata, CONFIGURATION, None).unwrap();
        let cache = DisplayCache::new(vec![metadata], vec![]).unwrap();
        let card = cache.card(&credential(), &language, &wording(template));
        card.issuer().as_str().to_owned()
    };
    let named = || Some(json!([{"name": "Example University", "locale": "en-US"}]));
    let rows = [
        (named(), None, "Example University"),
        (
            named(),
            Some("Issued by {issuer}"),
            "Issued by Example University",
        ),
        (None, Some("Issued by {issuer}"), "Unknown issuer"),
    ];
    for (display, template, line) in rows {
        assert_eq!(card(display, template), line, "{template:?}");
    }
}

#[test]
fn an_issuer_template_has_its_placeholder_once_in_safe_text() {
    let long = format!("{}{{issuer}}", "a".repeat(TEMPLATE_MAX + 1));
    let rows: [(&str, Result<(), TemplateError>); 5] = [
        ("{issuer}, issuer", Ok(())),
        ("Issued by", Err(TemplateError::Placeholder)),
        ("{issuer} and {issuer}", Err(TemplateError::Placeholder)),
        (
            "\u{202e}{issuer}",
            Err(TemplateError::Text(TextError::Unsafe)),
        ),
        (&long, Err(TemplateError::Text(TextError::TooLong))),
    ];
    for (template, expected) in rows {
        assert_eq!(
            IssuerTemplate::parse(template).map(|_| ()),
            expected,
            "{template}"
        );
    }
}

/// A blank OPTIONAL display member reads as absent (OpenID4VCI 1.0, Section 12.2.4): the
/// issuer's `name`, a claim's `name` and a logo's `alt_text`, which the host's wording, the
/// claim key or nothing then stand for. A blank REQUIRED label is refused: the credential's
/// display `name`, and the Type Metadata display `name` and claim `label`.
#[test]
fn a_blank_optional_name_is_absent_and_a_blank_required_one_refused() {
    let language = Locale::parse("en-US").unwrap();
    let issuer = |edit: &dyn Fn(&mut Value)| {
        let mut issuer = json!({
            "credential_issuer": ISSUER,
            "credential_endpoint": "https://issuer.example/credential",
            "credential_configurations_supported": serde_json::from_str::<Value>(CONFIGURATIONS)
                .unwrap()
        });
        edit(&mut issuer);
        IssuerMetadata::merge(&issuer, CONFIGURATION, None)
    };

    let cache = |metadata: IssuerMetadata| DisplayCache::new(vec![metadata], vec![]).unwrap();

    let named = issuer(&|i| i["display"] = json!([{"name": " ", "locale": "en-US"}])).unwrap();
    let card = cache(named).card(&credential(), &language, &wording(None));
    assert_eq!(
        card.issuer().as_str(),
        "Unknown issuer",
        "the issuer's blank name"
    );

    let claim = issuer(&|i| metadata(i)["claims"][0]["display"][0]["name"] = json!(" ")).unwrap();
    let rows = cache(claim)
        .claim_rows(&credential(), &[pointer(&["given_name"])], &language)
        .unwrap();
    assert_eq!(
        rows[0].label().as_str(),
        "given_name",
        "a claim's blank name"
    );

    let logo = issuer(&|i| metadata(i)["display"][0]["logo"]["alt_text"] = json!("")).unwrap();
    let card = cache(logo).card(&credential(), &language, &wording(None));
    assert!(
        card.logo().unwrap().alt_text().is_none(),
        "a logo's blank alt_text"
    );

    let title = issuer(&|i| metadata(i)["display"][0]["name"] = json!(" "));
    assert_eq!(
        title.err(),
        Some(siros_display::DisplayError::Text(TextError::Empty)),
        "the credential's blank display name"
    );
    let type_metadata = |display: Value, claims: Value| {
        siros_display::TypeMetadata::parse(
            &json!({"vct": CONFIGURATION, "display": display, "claims": claims}),
        )
        .map(drop)
        .map_err(|error| error.code())
    };
    let label = |text: &str| json!([{"path": ["given_name"], "display": [{"locale": "fr", "label": text}]}]);
    assert_eq!(
        type_metadata(json!([{"locale": "fr", "name": " "}]), label("Prénom")),
        Err("text_empty"),
        "the Type Metadata's blank display name"
    );
    assert_eq!(
        type_metadata(json!([{"locale": "fr", "name": "Identité"}]), label(" ")),
        Err("text_empty"),
        "a Type Metadata claim's blank label"
    );
}

/// The `credential_metadata` of the configuration in `issuer`.
fn metadata(issuer: &mut Value) -> &mut Value {
    &mut issuer["credential_configurations_supported"][CONFIGURATION]["credential_metadata"]
}
