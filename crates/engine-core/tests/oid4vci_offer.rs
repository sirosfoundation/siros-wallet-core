//! The credential offer's strict decode (pkg/strictjson's
//! unknown-member rejection, go-wallet-backend 2a6fd510): a
//! third-party offer document carries nothing beyond the offer
//! schema's members, where the flow start's by-value params — the
//! wallet's own merge — carry the wallet's members beside the offer's.

use engine_core::oid4vci::offer::parse_offer;
use engine_core::oid4vci::types::OfferError;
use engine_ports::{HttpClient, HttpError, HttpRequest, HttpResponse};

/// The HTTP the document tests never reach.
struct UnusedHttp;

#[async_trait::async_trait]
impl HttpClient for UnusedHttp {
    async fn send(&self, _request: HttpRequest) -> Result<HttpResponse, HttpError> {
        Err(HttpError::Refused)
    }
}

/// The offer the strict decode accepts: the schema's members alone
/// (OID4VCI §4.1.1).
#[tokio::test]
async fn a_clean_offer_document_parses() {
    let offer = parse_offer(
        &UnusedHttp,
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
    let refusal = parse_offer(&UnusedHttp, &serde_json::json!(uri))
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
        &UnusedHttp,
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
