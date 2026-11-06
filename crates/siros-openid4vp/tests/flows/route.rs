//! The errors on an authenticated request's route (section 8.2's error recourse): A.4's error
//! over the DC API, which the core writes for every DC API route (KA15), or a cancelled flow; by
//! URI the error mode's body to the bound `response_uri`, sealed by the core to the key the
//! answering mode bound, else in the clear; `Unroutable` for a URI mode no error mode carries.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use siros_openid4vp::matching::{Accepted, UnmetCode};
use siros_openid4vp::recourse::{DcApiErrors, Reply};
use siros_openid4vp::refusal::{ErrorCode, Refusal, Refused, RequestRule};
use siros_openid4vp::request::Request;
use siros_openid4vp::resolve::{Delivery, Outcome, PostBody, Route};
use siros_testkit::{TestHost, TestTrust, fixtures};

use super::{
    KEY, RESPONSE_URI, authenticated, config, envelope, fetched, link, registry, request_object,
    uri_payload,
};

/// The pairs of a form body, in order.
fn pairs(body: &PostBody) -> Vec<(String, String)> {
    assert!(body.media_type().is_form(), "{}", body.media_type());
    serde_urlencoded::from_bytes(body.bytes()).expect("a form")
}

/// The JSON of a DC API delivery.
fn dc_api(reply: Reply) -> Value {
    let Reply::Deliver(Delivery::DcApi(data)) = reply else {
        panic!("A.4's error, got {reply:?}")
    };
    serde_json::from_str(data.as_str()).expect("JSON")
}

/// The form of a POST to the test Verifier's Response URI.
fn posted(delivery: Delivery) -> Vec<(String, String)> {
    let Delivery::Post { endpoint, body } = delivery else {
        panic!("a POST, got {delivery:?}")
    };
    assert_eq!(endpoint.as_str(), RESPONSE_URI);
    pairs(&body)
}

/// The header and plaintext of the test `Haip`'s stand-in JWE.
fn stand_in(jwe: &str) -> (Value, Value) {
    let parts: Vec<&str> = jwe.split('.').collect();
    let [header, "", "", plaintext, ""] = parts.as_slice() else {
        panic!("five parts: {jwe}")
    };
    let read = |part: &str| -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("JSON")
    };
    (read(header), read(plaintext))
}

/// The refusals of a request: its parse's, else its acceptance's under the test registry.
fn refused(request: Result<Request<'_>, Refused>) -> Refused {
    match request {
        Err(refused) => refused,
        Ok(request) => match Accepted::new(&request, &registry()) {
            Err(refused) => refused,
            Ok(_) => panic!("a refused request"),
        },
    }
}

/// Runs `check` on the route of a URI request whose Request Object's payload is `payload`, and
/// on the request's refusals when it breaks a rule.
fn by_uri<R>(
    payload: &str,
    check: impl FnOnce(Result<&Route<'_, TestHost>, &Outcome>, Option<Refused>) -> R,
) -> R {
    let uri = link("test%3Averifier", "");
    let object = request_object(payload);
    let received = fetched(&uri, &object).expect("fetched");
    let envelope = envelope(&received);
    let registry = registry();
    let authenticated =
        authenticated(&envelope, &registry, &TestTrust::default(), &config()).expect("authentic");
    let refusals = match Request::parse(authenticated.envelope()) {
        Err(refused) => Some(refused),
        Ok(request) => Accepted::new(&request, &registry).err(),
    };
    let host = TestHost::default();
    let route = Route::new(&authenticated, &registry, &host);
    check(route.as_ref(), refusals)
}

/// A payload with a member replaced, as [`uri_payload`] writes it.
fn with(from: &str, to: &str) -> String {
    let payload = uri_payload("");
    assert!(payload.contains(from), "{from}");
    payload.replacen(from, to, 1)
}

#[test]
fn a_dc_api_route_answers_errors_as_a_4_or_cancels() {
    let host = TestHost::default();
    let registry = registry();
    let cases = [
        // KA15: an invalid_request refusal over dc_api (A.4's example error).
        r#"{"response_type":"vp_token","response_mode":"dc_api","nonce":"n-0S6_WzA2Mj"}"#,
        // A request naming no registered DC API mode: C5, A.4's error from the core.
        r#"{"response_type":"vp_token","response_mode":"fragment","nonce":"n-0S6_WzA2Mj","dcql_query":{"credentials":[{"id":"q","format":"test"}]}}"#,
    ];
    for parameters in cases {
        let received = fixtures::unsigned(parameters).expect("received");
        let envelope = envelope(&received);
        let authenticated = authenticated(&envelope, &registry, &TestTrust::default(), &config())
            .expect("authentic");
        let refusals = refused(Request::parse(authenticated.envelope()));
        let route = Route::new(&authenticated, &registry, &host).expect("a DC API route");
        assert!(route.answering().is_none() || parameters.contains("\"dc_api\""));
        assert_eq!(
            dc_api(
                route
                    .refusal(&refusals, DcApiErrors::Respond, &host)
                    .expect("a reply")
            ),
            json!({"error": "invalid_request"}),
            "{parameters}"
        );
        assert!(matches!(
            route.refusal(&refusals, DcApiErrors::Cancel, &host),
            Ok(Reply::Cancel)
        ));
        assert_eq!(
            dc_api(
                route
                    .unmet(
                        UnmetCode::VpFormatsNotSupported,
                        DcApiErrors::Respond,
                        &host
                    )
                    .expect("a reply")
            ),
            json!({"error": "vp_formats_not_supported"})
        );
        assert!(matches!(
            route.unmet(UnmetCode::AccessDenied, DcApiErrors::Cancel, &host),
            Ok(Reply::Cancel)
        ));
    }
}

#[test]
fn a_uri_route_seals_its_errors_to_the_bound_key_else_sends_them_plain() {
    let host = TestHost::default();
    // A route whose mode bound B.2.6's key: the error sealed by the core with A128GCM (the
    // Verifier lists no enc, §5.1), wrapped as response=<JWE>.
    by_uri(&uri_payload(""), |route, _| {
        let route = route.expect("a route");
        assert!(route.answering().is_some());
        let unmet = route
            .unmet(UnmetCode::AccessDenied, DcApiErrors::Cancel, &host)
            .expect("a reply");
        let Reply::Deliver(delivery) = unmet else {
            panic!("an error by URI is delivered")
        };
        let form = posted(delivery);
        let [(name, jwe)] = form.as_slice() else {
            panic!("response alone: {form:?}")
        };
        assert_eq!(name, "response");
        let (header, plaintext) = stand_in(jwe);
        assert_eq!(
            (&header["kid"], &header["enc"]),
            (&json!("1"), &json!("A128GCM"))
        );
        assert_eq!(
            plaintext,
            json!({"error": "access_denied", "state": "eyJhb-6-sVA"})
        );
        let (_, plaintext) = stand_in(&posted(route.unavailable(&host).expect("a delivery"))[0].1);
        assert_eq!(plaintext["error"], "wallet_unavailable");
    });
    // C7: no key the rule accepts; the request's error goes plain (§8.3.1).
    let keyless = with(
        KEY,
        &KEY.replace(r#","alg":"ECDH-ES""#, r#","alg":"RSA-OAEP""#),
    );
    by_uri(&keyless, |route, refusals| {
        let route = route.expect("a route");
        assert!(route.answering().is_none(), "C7 leaves no answering route");
        let refusals = refusals.expect("C7");
        let Ok(Reply::Deliver(delivery)) = route.refusal(&refusals, DcApiErrors::Cancel, &host)
        else {
            panic!("an error by URI is delivered")
        };
        let form = posted(delivery);
        let names: Vec<&str> = form.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["error", "error_description", "state"]);
        assert_eq!(form[0].1, "invalid_request");
        assert!(form[1].1.starts_with("C7 direct_post.jwt"), "{}", form[1].1);
        assert_eq!(form[2].1, "eyJhb-6-sVA");
    });
    // C5 for direct_post, which carries errors alone: its error plain to the response_uri
    // (reading 24).
    let errors_alone = with(
        r#""response_mode":"direct_post.jwt""#,
        r#""response_mode":"direct_post""#,
    );
    by_uri(&errors_alone, |route, refusals| {
        let route = route.expect("a route");
        assert!(route.answering().is_none());
        let refusals = refusals.expect("C5");
        let Ok(Reply::Deliver(delivery)) = route.refusal(&refusals, DcApiErrors::Respond, &host)
        else {
            panic!("an error by URI is delivered")
        };
        let form = posted(delivery);
        assert_eq!(form[0], ("error".to_owned(), "invalid_request".to_owned()));
        assert!(form[1].1.starts_with("C5 response_mode"), "{}", form[1].1);
    });
    // C5 by URI for a mode no error mode carries: Unroutable, the End-User alone.
    let unsupported = with(
        r#""response_mode":"direct_post.jwt""#,
        r#""response_mode":"fragment""#,
    );
    by_uri(&unsupported, |route, _| {
        assert!(matches!(route, Err(Outcome::Unroutable(_))));
    });
}

/// §8.2's example error: `invalid_request`, `unsupported client_id_prefix`, `state`
/// `eyJhb...6-sVA`.
#[derive(Debug, thiserror::Error, siros_explain::Explain)]
#[explain(domain = "test.ka8")]
#[error("unsupported client_id_prefix")]
struct Section82;

impl RequestRule for Section82 {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_REQUEST
    }
}

/// KA8: §8.2's example error body, in this order, as RFC 6749 Appendix B encodes it (a space is
/// `+`), from `direct_post` and from `direct_post.jwt` on a route without a key (§8.3.1).
#[test]
fn section_8_2s_error_body_is_each_uri_error_modes_plain_form() {
    const SECTION_8_2: &str = "error=invalid_request\
        &error_description=unsupported+client_id_prefix\
        &state=eyJhb...6-sVA";
    let host = TestHost::default();
    let state = |payload: String| {
        payload.replacen(r#""state":"eyJhb-6-sVA""#, r#""state":"eyJhb...6-sVA""#, 1)
    };
    let direct_post = with(
        r#""response_mode":"direct_post.jwt""#,
        r#""response_mode":"direct_post""#,
    );
    // C7 leaves direct_post.jwt's route without a key.
    let keyless = with(
        KEY,
        &KEY.replace(r#","alg":"ECDH-ES""#, r#","alg":"RSA-OAEP""#),
    );
    for payload in [direct_post, keyless].map(state) {
        by_uri(&payload, |route, _| {
            let route = route.expect("a route");
            assert!(route.answering().is_none(), "{payload}");
            let refused = Refused::one(Refusal::new(Section82));
            let Ok(Reply::Deliver(Delivery::Post { endpoint, body })) =
                route.refusal(&refused, DcApiErrors::Respond, &host)
            else {
                panic!("an error by URI is delivered")
            };
            assert_eq!(endpoint.as_str(), RESPONSE_URI);
            assert!(body.media_type().is_form(), "{payload}");
            assert_eq!(
                std::str::from_utf8(body.bytes()),
                Ok(SECTION_8_2),
                "{payload}"
            );
        });
    }
}
