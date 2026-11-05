//! The error's form a rejection replies with: §8.2's plain error POST body by URI, and A.4's
//! error over the DC API (KA15).

use serde_json::Value;
use siros_openid4vp::arrival::{DcApiProtocols, Received};
use siros_openid4vp::ids::Origin;
use siros_openid4vp::recourse::{DcApiErrors, Rejected, Reply};
use siros_openid4vp::refusal::ErrorCode;
use siros_openid4vp::resolve::{Delivery, PostBody};

/// The pairs of a form body, in order.
fn pairs(body: &PostBody) -> Vec<(String, String)> {
    assert!(body.media_type().is_form(), "{}", body.media_type());
    serde_urlencoded::from_bytes(body.bytes()).expect("a form")
}

/// A rejection's error by URI is the same plain form, to the route's `response_uri`: U10's code
/// (RFC 9101 §7), its description, `state` as received.
#[test]
fn a_rejections_error_by_uri_is_the_plain_form() {
    use super::{RESPONSE_URI, b64, fetched, link, uri_payload};
    let uri = link("test%3Averifier", "");
    let none = format!(
        "{}.{}.{}",
        b64(r#"{"alg":"none"}"#),
        b64(&uri_payload("")),
        b64("x")
    );
    let rejected = fetched(&uri, &none).expect_err("U10");
    let Ok(Reply::Deliver(Delivery::Post { endpoint, body })) = rejected.reply(DcApiErrors::Cancel)
    else {
        panic!("a POST of the error")
    };
    assert_eq!(endpoint.as_str(), RESPONSE_URI);
    let pairs = pairs(&body);
    let names: Vec<&str> = pairs.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["error", "error_description", "state"]);
    assert_eq!(pairs[0].1, "invalid_request_object");
    assert_eq!(pairs[2].1, "eyJhb-6-sVA");
}

/// KA15: A.4's example error, `{"error": "invalid_request"}`, for a DC API request refused with
/// `invalid_request` under `DcApiErrors::Respond`; a cancelled flow under `DcApiErrors::Cancel`
/// (§15.9.2).
#[test]
fn a_dc_api_refusal_is_a_4s_error_or_a_cancelled_flow() {
    let origin = Origin::parse("https://verifier.example").expect("origin");
    let cause = Received::dc_api("openid4vp-v1-unsigned", "{", origin, &DcApiProtocols::ALL)
        .expect_err("U3");
    let rejected = Rejected::dc_api(cause);
    assert_eq!(
        rejected.failure().code(),
        Some(ErrorCode::INVALID_REQUEST),
        "{}",
        rejected.failure()
    );
    let Ok(Reply::Deliver(Delivery::DcApi(data))) = rejected.reply(DcApiErrors::Respond) else {
        panic!("A.4's error")
    };
    let data: Value = serde_json::from_str(data.as_str()).expect("JSON");
    assert_eq!(data, serde_json::json!({"error": "invalid_request"}));
    assert!(matches!(
        rejected.reply(DcApiErrors::Cancel),
        Ok(Reply::Cancel)
    ));
}
