//! The envelope: `typ` (U12), nesting (U13), the payload's JSON (U3), `crit` (U16) and a
//! multisigned request's `client_id` placement (U17), each with the route its error takes.

use siros_openid4vp::arrival::{DcApiProtocols, Received, Unreadable};
use siros_openid4vp::envelope::{ClientIdPlacement, Envelope, NestedParameter, Signatures};
use siros_openid4vp::ids::Origin;
use siros_openid4vp::jose::JwsError;
use siros_openid4vp::json::JsonError;
use siros_openid4vp::recourse::{ErrorTarget, Failure, Rejected};
use siros_testkit::jose::{VERIFIER_SECRET, compact_jws, sign};

use super::{RESPONSE_URI, b64, fetched, link, request_object, uri_payload};

/// The envelope's refusal of a Request Object fetched by URI, and the route `Rejected::unreadable`
/// gives it.
fn refused(object: &str) -> (Unreadable, Option<ErrorTarget>) {
    let uri = link("test%3Averifier", "");
    let received = fetched(&uri, object).expect("fetched");
    let cause = Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .map(drop)
    .expect_err("refused");
    let rejected = Rejected::unreadable(&received, cause.clone());
    (cause, rejected.route().map(|route| route.target().clone()))
}

fn unverified(target: Option<ErrorTarget>) -> bool {
    matches!(target, Some(ErrorTarget::Unverified(uri)) if uri.as_str() == RESPONSE_URI)
}

#[test]
fn a_request_object_names_its_type_and_nests_no_request() {
    let payload = uri_payload("");
    // U12: typ absent, and typ JWT.
    for header in [r#"{"alg":"ES256"}"#, r#"{"alg":"ES256","typ":"JWT"}"#] {
        let (cause, target) =
            refused(&compact_jws(&VERIFIER_SECRET, header, &payload).expect("signs"));
        assert!(matches!(cause, Unreadable::Typ { .. }), "{cause:?}");
        assert!(unverified(target), "U12 by URI: unverified");
    }
    // RFC 7515 §4.1.9: `application/` prefixed, case-insensitively.
    let full = compact_jws(
        &VERIFIER_SECRET,
        r#"{"alg":"ES256","typ":"Application/OAuth-Authz-Req+JWT"}"#,
        &payload,
    )
    .expect("signs");
    let uri = link("test%3Averifier", "");
    let received = fetched(&uri, &full).expect("fetched");
    assert!(
        Envelope::parse(
            &received,
            siros_testkit::fixtures::routing().expect("the routing registry")
        )
        .is_ok()
    );
    // U13: a Request Object holding request_uri.
    let (cause, target) = refused(&request_object(&uri_payload(
        r#","request_uri":"https://verifier.example/r""#,
    )));
    assert_eq!(
        cause,
        Unreadable::Nested {
            parameter: NestedParameter::RequestUri
        }
    );
    assert!(unverified(target));
    // U3: the payload's member twice is the json module's refusal; no route without a payload.
    let (cause, target) = refused(&request_object(&uri_payload(r#","nonce":"again""#)));
    assert_eq!(
        cause,
        Unreadable::Json(JsonError::DuplicateMember {
            member: "nonce".to_owned()
        })
    );
    assert!(target.is_none());
    assert_eq!(
        Failure::Unreadable(cause).code().map(|code| code.as_str()),
        Some("invalid_request")
    );
}

#[test]
fn crit_is_refused_by_u16_with_an_unverified_route() {
    let uri = link("test%3Averifier", "");
    let object = compact_jws(
        &VERIFIER_SECRET,
        r#"{"alg":"ES256","typ":"oauth-authz-req+jwt","crit":["exp"]}"#,
        &uri_payload(""),
    )
    .expect("signs");
    let rejected = fetched(&uri, &object).expect_err("U16");
    assert!(matches!(
        rejected.failure(),
        Failure::Unreadable(Unreadable::Jws(JwsError::Critical { header })) if header == "exp"
    ));
    assert!(unverified(
        rejected.route().map(|route| route.target().clone())
    ));
}

/// A multisigned DC API request of the parameters, each signature's protected header naming a
/// Client Identifier, its unprotected header as given.
fn multisigned(parameters: &str, unprotected: &[Option<&str>]) -> String {
    let payload = b64(parameters);
    let signatures: Vec<String> = unprotected
        .iter()
        .enumerate()
        .map(|(k, header)| {
            // A Client Identifier moved into the unprotected header leaves the protected one.
            let client_id = if header.is_some_and(|h| h.contains("client_id")) {
                String::new()
            } else {
                format!(r#","client_id":"test:signer{k}""#)
            };
            let protected = b64(&format!(
                r#"{{"alg":"ES256","typ":"oauth-authz-req+jwt"{client_id}}}"#
            ));
            let signature =
                sign(&VERIFIER_SECRET, &format!("{protected}.{payload}")).expect("signs");
            let header = header.map_or_else(String::new, |h| format!(r#","header":{h}"#));
            format!(r#"{{"protected":"{protected}"{header},"signature":"{signature}"}}"#)
        })
        .collect();
    format!(
        r#"{{"payload":"{payload}","signatures":[{}]}}"#,
        signatures.join(",")
    )
}

#[test]
fn a_multisigned_request_names_client_id_in_its_protected_headers_alone() {
    let parameters = super::common::parameters(&super::test_queries(&["q"]), "");
    let origin = || Origin::parse("https://verifier.example").expect("origin");
    let data = multisigned(&parameters, &[None, None]);
    let received = Received::dc_api(
        "openid4vp-v1-multisigned",
        &data,
        origin(),
        &DcApiProtocols::ALL,
    )
    .expect("received");
    let envelope = Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .expect("an envelope");
    assert!(matches!(envelope.signatures(), Signatures::Many(_)));
    assert!(
        envelope.client_id().is_none(),
        "each signature names its own"
    );
    // U17: client_id in the payload; tamper: client_id moved into an unprotected header.
    let with = super::common::parameters(&super::test_queries(&["q"]), r#""client_id":"test:x""#);
    let cases = [
        (multisigned(&with, &[None]), ClientIdPlacement::Payload),
        (
            multisigned(&parameters, &[None, Some(r#"{"client_id":"test:x"}"#)]),
            ClientIdPlacement::UnprotectedHeader,
        ),
    ];
    for (data, member) in cases {
        let received = Received::dc_api(
            "openid4vp-v1-multisigned",
            &data,
            origin(),
            &DcApiProtocols::ALL,
        )
        .expect("received");
        let cause = Envelope::parse(
            &received,
            siros_testkit::fixtures::routing().expect("the routing registry"),
        )
        .map(drop)
        .expect_err("U17");
        assert_eq!(cause, Unreadable::Placement { member });
        let rejected = Rejected::unreadable(&received, cause);
        assert_eq!(
            rejected.route().map(|route| route.target().clone()),
            Some(ErrorTarget::DcApi)
        );
        assert_eq!(
            rejected.failure().code().map(|code| code.as_str()),
            Some("invalid_request")
        );
    }
    // U3: a protected header's client_id outside RFC 6749 Appendix A.1, or no string.
    let payload = b64(&parameters);
    for (client_id, named) in [(r#""test:\u00e9""#, "test:\u{e9}"), ("7", "7")] {
        let protected = b64(&format!(
            r#"{{"alg":"ES256","typ":"oauth-authz-req+jwt","client_id":{client_id}}}"#
        ));
        let signature = sign(&VERIFIER_SECRET, &format!("{protected}.{payload}")).expect("signs");
        let data = format!(
            r#"{{"payload":"{payload}","signatures":[{{"protected":"{protected}","signature":"{signature}"}}]}}"#
        );
        let received = Received::dc_api(
            "openid4vp-v1-multisigned",
            &data,
            origin(),
            &DcApiProtocols::ALL,
        )
        .expect("received");
        let cause = Envelope::parse(
            &received,
            siros_testkit::fixtures::routing().expect("the routing registry"),
        )
        .map(drop)
        .expect_err("U3");
        assert_eq!(
            cause,
            Unreadable::ClientId {
                client_id: named.to_owned()
            }
        );
    }
}
