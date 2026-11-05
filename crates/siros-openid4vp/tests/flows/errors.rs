//! The error's form: §8.2's plain error POST body, which the core's URI error modes write (KA8),
//! and A.4's error over the DC API, which the core writes (KA15).

use std::borrow::Cow;

use serde_json::Value;
use siros_openid4vp::arrival::{DcApiProtocols, Received};
use siros_openid4vp::ids::Origin;
use siros_openid4vp::modes::{DirectPost, DirectPostJwt};
use siros_openid4vp::recourse::{DcApiErrors, Rejected, Reply};
use siros_openid4vp::refusal::{ErrorCode, ErrorDescription};
use siros_openid4vp::resolve::{Delivery, ErrorContent, ErrorResponse, ModeRoute, PostBody};
use siros_openid4vp::routing::{Echo, ErrorModeHost};
use siros_testkit::TestHost;

/// The pairs of a form body, in order.
fn pairs(body: &PostBody) -> Vec<(String, String)> {
    assert!(body.media_type().is_form(), "{}", body.media_type());
    serde_urlencoded::from_bytes(body.bytes()).expect("a form")
}

/// KA8: §8.2's example error POST body, `error=invalid_request&error_description=unsupported
/// %20client_id_prefix&state=eyJhb...6-sVA`, in this order, from `direct_post` and from
/// `direct_post.jwt` on a route without a key (§8.3.1).
#[test]
fn section_8_2s_error_body_is_each_uri_error_modes_plain_form() {
    let section_8_2 = [
        ("error", "invalid_request"),
        ("error_description", "unsupported client_id_prefix"),
        ("state", "eyJhb...6-sVA"),
    ]
    .map(|(name, value)| (name.to_owned(), value.to_owned()));
    let echo = Echo::new(Cow::Borrowed("eyJhb...6-sVA"));
    let error = ErrorResponse::new(
        ErrorCode::INVALID_REQUEST,
        ErrorDescription::sanitized("unsupported client_id_prefix"),
        Some(echo.clone()),
    );
    let route = ModeRoute::new(None, Some(&echo));
    let content = ErrorContent::Clear(&error);
    let host = TestHost::default();
    let modes: [&dyn ErrorModeHost<TestHost>; 2] = [&DirectPost, &DirectPostJwt];
    for mode in modes {
        let body = mode.error(&route, &content, &host).expect("a body");
        assert_eq!(pairs(&body), section_8_2, "{}", mode.name());
    }
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
