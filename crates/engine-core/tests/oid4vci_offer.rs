use engine_core::oid4vci::offer::*;
use engine_core::oid4vci::types::OfferError;
use engine_ports::{HttpClient, HttpError, HttpRequest};

/// A fake HTTP client that answers with a canned offer.
struct FakeHttp {
    body: Vec<u8>,
    status: u16,
}

#[async_trait::async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, _request: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
        Ok(engine_ports::HttpResponse {
            status: self.status,
            headers: Vec::new(),
            body: self.body.clone(),
        })
    }
}

fn offer_json() -> serde_json::Value {
    serde_json::json!({
        "credential_issuer": "https://issuer.example",
        "credential_configuration_ids": ["UniversityDegree"],
        "grants": { "authorization_code": {} }
    })
}

#[tokio::test]
async fn parses_an_offer_by_value() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    let offer = parse_offer(&http, &offer_json()).await.expect("parse");
    assert_eq!(offer.credential_issuer, "https://issuer.example");
    assert_eq!(offer.credential_configuration_ids, ["UniversityDegree"]);
}

#[tokio::test]
async fn refuses_an_offer_with_no_issuer() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    let bad = serde_json::json!({
        "credential_configuration_ids": ["X"]
    });
    assert!(matches!(
        parse_offer(&http, &bad).await,
        Err(OfferError::NoIssuer)
    ));
}

#[tokio::test]
async fn refuses_an_offer_with_no_configuration_ids() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    let bad = serde_json::json!({
        "credential_issuer": "https://issuer.example"
    });
    assert!(matches!(
        parse_offer(&http, &bad).await,
        Err(OfferError::NoConfigurationIds)
    ));
}

#[tokio::test]
async fn fetches_an_offer_by_reference() {
    let offer_text = serde_json::to_string(&offer_json()).expect("serialize");
    let http = FakeHttp {
        body: offer_text.into_bytes(),
        status: 200,
    };
    let params = serde_json::json!({
        "credential_offer_uri": "https://issuer.example/offer"
    });
    let offer = parse_offer(&http, &params).await.expect("parse");
    assert_eq!(offer.credential_issuer, "https://issuer.example");
}

#[tokio::test]
async fn parses_the_uri_scheme_with_the_double_slash() {
    let offer_text = serde_json::to_string(&offer_json()).expect("serialize");
    let http = FakeHttp {
        body: offer_text.into_bytes(),
        status: 200,
    };
    let uri =
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer";
    let offer = parse_offer(&http, &serde_json::json!(uri))
        .await
        .expect("parse");
    assert_eq!(offer.credential_issuer, "https://issuer.example");
}

#[tokio::test]
async fn parses_the_uri_scheme_bare_form() {
    let offer_text = serde_json::to_string(&offer_json()).expect("serialize");
    let http = FakeHttp {
        body: offer_text.into_bytes(),
        status: 200,
    };
    let uri = "openid-credential-offer:?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer";
    let offer = parse_offer(&http, &serde_json::json!(uri))
        .await
        .expect("parse");
    assert_eq!(offer.credential_issuer, "https://issuer.example");
}

#[tokio::test]
async fn refuses_a_non_200_offer_fetch() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 404,
    };
    let params = serde_json::json!({
        "credential_offer_uri": "https://issuer.example/missing"
    });
    assert!(matches!(
        parse_offer(&http, &params).await,
        Err(OfferError::Fetch(_))
    ));
}
#[tokio::test]
async fn parses_an_offer_from_the_credential_offer_uri_scheme_by_value() {
    // The OIDF suite's by-value form: the offer JSON rides in the
    // credential_offer= query parameter (OpenID4VCI 1.0 §4.1).
    let http = FakeHttp {
        status: 500,
        body: Vec::new(),
    };
    let offer_json = serde_json::json!({
        "credential_issuer": "https://issuer.example",
        "credential_configuration_ids": ["eu.europa.ec.eudi.pid.1"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "preauth-1",
                "tx_code": {"length": 6, "input_mode": "numeric"}
            }
        }
    });
    // The minimal percent-encoding the parser's urldecode undoes:
    // braces, quotes, colons.
    let text = offer_json.to_string();
    let mut encoded = String::new();
    for b in text.bytes() {
        match b {
            b'{' | b'}' | b'"' | b':' | b' ' | b'[' | b']' | b',' | b'/' | b'=' | b'+' | b'#'
            | b'&' | b'?' | b'%' => {
                encoded.push_str(&format!("%{b:02X}"));
            }
            _ => encoded.push(b as char),
        }
    }
    let uri = format!("openid-credential-offer://?credential_offer={encoded}");
    let params = serde_json::Value::String(uri);
    let offer = parse_offer(&http, &params).await.expect("parse");
    assert_eq!(offer.credential_issuer, "https://issuer.example");
    assert_eq!(
        offer.credential_configuration_ids,
        vec!["eu.europa.ec.eudi.pid.1".to_owned()]
    );
    assert!(offer
        .grants
        .get("urn:ietf:params:oauth:grant-type:pre-authorized_code")
        .is_some());
}
