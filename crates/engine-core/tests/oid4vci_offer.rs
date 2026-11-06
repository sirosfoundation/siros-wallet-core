//! The credential offer's strict decode (pkg/strictjson's
//! unknown-member rejection, go-wallet-backend 2a6fd510): a
//! third-party offer document carries nothing beyond the offer
//! schema's members, where the flow start's by-value params — the
//! wallet's own merge — carry the wallet's members beside the offer's.

use engine_core::oid4vci::offer::parse_offer;
use engine_core::oid4vci::types::OfferError;
use engine_ports::{HttpClient, HttpError, HttpRequest, HttpResponse};

/// A fake HTTP client that answers with a canned offer.
struct FakeHttp {
    body: Vec<u8>,
    status: u16,
}

#[async_trait::async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, _request: HttpRequest) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: self.status,
            headers: Vec::new(),
            body: self.body.clone(),
        })
    }
}

/// The HTTP the document tests never reach: a fetch through it fails.
fn unused_http() -> FakeHttp {
    FakeHttp {
        body: Vec::new(),
        status: 500,
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
    let http = unused_http();
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
    let encoded = urlencode(&offer_json.to_string());
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

/// The offer the strict decode accepts: the schema's members alone
/// (OID4VCI §4.1.1).
#[tokio::test]
async fn a_clean_offer_document_parses() {
    let offer = parse_offer(
        &unused_http(),
        &serde_json::json!({
            "credential_issuer": "https://issuer.example",
            "credential_configuration_ids": ["UniversityDegree"],
            "grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {"pre-authorized_code": "code-1"}},
        }),
    )
    .await
    .expect("the schema's members alone parse");
    assert_eq!(offer.credential_issuer, "https://issuer.example");
    assert_eq!(offer.credential_configuration_ids, ["UniversityDegree"]);
}

/// A third-party offer document carrying a member the schema does not
/// define refuses — the superseded SIROS secret shape
/// (`secret_seed`) is an ordinary unknown member now, and where two
/// parties read one document, an unknown member would let them differ.
#[tokio::test]
async fn an_unknown_member_in_a_document_refuses() {
    // The document form: the offer carried by the URI scheme's
    // `credential_offer` parameter (URL-encoded JSON).
    let document = serde_json::json!({
        "credential_issuer": "https://issuer.example",
        "credential_configuration_ids": ["UniversityDegree"],
        "grants": {},
        "secret_seed": "c2VjcmV0",
    })
    .to_string();
    let uri = format!(
        "openid-credential-offer:?credential_offer={}",
        urlencode(&document),
    );
    let refusal = parse_offer(&unused_http(), &serde_json::json!(uri))
        .await
        .expect_err("an unknown member refuses");
    assert!(matches!(refusal, OfferError::UnknownMember), "{refusal:?}");
}

/// The same members riding the flow start's by-value params parse: the
/// wallet authored that form itself, its own members beside the
/// offer's, so the strict decode does not apply there.
#[tokio::test]
async fn the_wallets_own_params_form_stays_lenient() {
    let offer = parse_offer(
        &unused_http(),
        &serde_json::json!({
            "credential_issuer": "https://issuer.example",
            "credential_configuration_ids": ["UniversityDegree"],
            "grants": {},
            "redirect_uri": "https://wallet.example/cb",
            "client_id": "client-1",
        }),
    )
    .await
    .expect("the wallet's merge parses");
    assert_eq!(offer.credential_issuer, "https://issuer.example");
}

/// Percent-encodes a query member's value.
fn urlencode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
