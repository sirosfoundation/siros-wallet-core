//! The three shapes a DC API request arrives in, and what happens to the ones
//! that arrive broken. Only `data` differs between them (OpenID4VP 1.0,
//! Appendix A). The payloads follow the specification; a capture from a real
//! verifier belongs in the device pass.

use siros_codec::base64url::encode as b64;
use siros_codec::json::JsonTextError;
use siros_codec::Base64Error;
use siros_dcql::{CredentialMember, FormFault, Member, Position, QueryError};
use siros_oid4vp::{diagnose, ClientId, CompactFault, NoQuery, PayloadFault, UnverifiedRequest};

/// The protocols SIROS wallets register: the three of OpenID4VP 1.0, A.1.
fn siros_default(label: &str) -> bool {
    matches!(
        label,
        "openid4vp-v1-unsigned" | "openid4vp-v1-signed" | "openid4vp-v1-multisigned"
    )
}

/// The first registered entry that reads, for the wallet's registration `registered`.
fn first(request: &[u8], registered: &dyn Fn(&str) -> bool) -> Option<UnverifiedRequest> {
    UnverifiedRequest::first_registered(request, registered)
}

/// The entry's protocol label and its DCQL query.
fn first_supported_request(
    request: &[u8],
    registered: &dyn Fn(&str) -> bool,
) -> Option<(String, siros_dcql::DcqlQuery)> {
    let found = first(request, registered)?;
    Some((found.protocol().label().to_owned(), found.query().clone()))
}

/// The authorization request object all three protocols ultimately carry.
fn request_object() -> String {
    serde_json::json!({
        "client_id": "x509_san_dns:verifier.example",
        "response_type": "vp_token",
        "response_mode": "dc_api.jwt",
        "nonce": "n-0S6_WzA2Mj",
        "expected_origins": ["https://verifier.example"],
        "dcql_query": {
            "credentials": [{
                "id": "pid",
                "format": "mso_mdoc",
                "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                "claims": [{"path": ["org.iso.18013.5.1", "age_over_18"]}]
            }]
        },
        "client_metadata": {"jwks": {"keys": []}}
    })
    .to_string()
}

/// The request object of a multisigned request: its Client Identifiers are its signatures'
/// (A.3.2.2).
fn multisigned_object() -> String {
    let mut object: serde_json::Value = serde_json::from_str(&request_object()).expect("json");
    object.as_object_mut().expect("object").remove("client_id");
    object.to_string()
}

/// The protected header of a Request Object's JWS that keeps the rules the picker reads.
const HEADER: &[u8] = br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#;

/// 64 bytes in place of an ES256 signature, which the picker never verifies.
fn bogus_signature() -> String {
    b64(&[7; 64]).to_string()
}

/// A signature of a multisigned request whose protected header names a Client Identifier.
fn signature() -> serde_json::Value {
    let header = br#"{"alg":"ES256","typ":"oauth-authz-req+jwt","client_id":"x509_san_dns:verifier.example"}"#;
    serde_json::json!({"protected": b64(header).to_string(), "signature": bogus_signature()})
}

/// A compact JWS of [`HEADER`] whose payload segment is `payload`, as written.
fn jws(payload: impl std::fmt::Display) -> String {
    format!("{}.{payload}.{}", b64(HEADER), bogus_signature())
}

fn envelope(protocol: &str, data: serde_json::Value) -> Vec<u8> {
    serde_json::json!({"requests": [{"protocol": protocol, "data": data}]})
        .to_string()
        .into_bytes()
}

fn compact_jws(payload: &str) -> String {
    jws(b64(payload.as_bytes()))
}

// --- the three shapes ------------------------------------------------------

/// `openid4vp-v1-unsigned`: the request object is `data` itself.
#[test]
fn an_unsigned_request_still_works() {
    let data: serde_json::Value = serde_json::from_str(&request_object()).expect("json");
    let found = first_supported_request(&envelope("openid4vp-v1-unsigned", data), &siros_default);
    let (protocol, query) = found.expect("unsigned request should be answered");
    assert_eq!(protocol, "openid4vp-v1-unsigned");
    assert_eq!(query.credentials().len(), 1);
}

/// `openid4vp-v1-signed`: `data.request` is a compact JWS whose middle segment
/// is the request object.
#[test]
fn a_signed_request_is_read_from_the_jws_payload() {
    let data = serde_json::json!({"request": compact_jws(&request_object())});
    let found = first_supported_request(&envelope("openid4vp-v1-signed", data), &siros_default);
    let (protocol, query) = found.expect("signed request should be answered");
    assert_eq!(protocol, "openid4vp-v1-signed");
    assert_eq!(query.credentials().len(), 1);
    assert_eq!(*query.credentials()[0].id(), "pid");
}

/// `openid4vp-v1-multisigned`: `data.request` is a JWS JSON Serialization
/// object, and the payload is one of its members.
#[test]
fn a_multisigned_request_is_read_from_the_payload_member() {
    let data = serde_json::json!({
        "request": {
            "payload": b64(multisigned_object().as_bytes()).to_string(),
            "signatures": [signature()]
        }
    });
    let found =
        first_supported_request(&envelope("openid4vp-v1-multisigned", data), &siros_default);
    let (_, query) = found.expect("multisigned request should be answered");
    assert_eq!(*query.credentials()[0].id(), "pid");
}

/// The reference matcher also accepts the serialization at the top level of
/// `data`, with no `request` wrapper. A verifier that sends it that way is not
/// wrong enough to refuse.
#[test]
fn a_multisigned_payload_at_the_top_level_of_data_is_accepted_too() {
    let data = serde_json::json!({
        "payload": b64(multisigned_object().as_bytes()).to_string(),
        "signatures": [signature()]
    });
    let found =
        first_supported_request(&envelope("openid4vp-v1-multisigned", data), &siros_default);
    assert!(found.is_some(), "top-level payload should be read");
}

// --- what the matcher is not -----------------------------------------------

/// The picker checks no signature: intake verifies the JWS at selection time,
/// before anything is disclosed.
#[test]
fn a_bogus_signature_does_not_stop_the_query_being_read() {
    let payload = b64(request_object().as_bytes());
    let data = serde_json::json!({
        "request": jws(payload),
    });
    assert!(
        first_supported_request(&envelope("openid4vp-v1-signed", data), &siros_default).is_some()
    );
}

// --- declining, rather than trapping ---------------------------------------

/// A trap shows the user nothing and is indistinguishable from "no matching
/// credential", so every malformed shape must decline instead.
#[test]
fn malformed_signed_requests_decline_without_panicking() {
    let profile = siros_default;
    for data in [
        serde_json::json!({"request": ""}),
        serde_json::json!({"request": "not-a-jws"}),
        serde_json::json!({"request": "onlyheader."}),
        serde_json::json!({"request": ".."}),
        serde_json::json!({"request": jws("!!!not-base64url!!!")}),
        serde_json::json!({"request": jws(b64(b"not json at all"))}),
        serde_json::json!({"request": jws(b64(br#"{"nonce":"x"}"#))}),
        serde_json::json!({"request": {"payload": "!!!"}}),
        serde_json::json!({"request": {"signatures": []}}),
        serde_json::json!({"request": 42}),
        serde_json::json!({}),
    ] {
        assert!(
            first_supported_request(&envelope("openid4vp-v1-signed", data.clone()), &profile)
                .is_none(),
            "should have declined: {data}"
        );
    }
}

/// Each failure is named, because "data has no `dcql_query`" is true of every
/// signed request and tells whoever is reading the picker nothing.
///
/// Keyed by protocol as well as by data, because the reason depends on both:
/// the same `{"request": 42}` is "not a compact JWS" under `-signed` and
/// "neither a JWS string nor a JWS JSON object" under `-multisigned`.
#[test]
fn each_failure_is_named_separately() {
    let cases = [
        (
            "openid4vp-v1-unsigned",
            serde_json::json!({"unrelated": true}),
            NoQuery::NoQueryAndNoRequest,
        ),
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": "no-dots"}),
            NoQuery::NotACompactJws(CompactFault::Segments),
        ),
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": "aGVhZGVy."}),
            NoQuery::NotACompactJws(CompactFault::Segments),
        ),
        // An empty header segment is malformed.
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": ".aGk.c2ln"}),
            NoQuery::NotACompactJws(CompactFault::EmptyHeader),
        ),
        // The compact serialization has three segments (RFC 7515 §7.1).
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": format!("aGVhZGVy.{}", b64(request_object().as_bytes()))}),
            NoQuery::NotACompactJws(CompactFault::Segments),
        ),
        // An inline query under the multisigned label is a mismatch.
        (
            "openid4vp-v1-multisigned",
            serde_json::json!({"dcql_query": {"credentials": []}}),
            NoQuery::ShapeDoesNotMatchProtocol,
        ),
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": jws("@@@@")}),
            NoQuery::PayloadNotBase64url(PayloadFault::Encoding(Base64Error::Alphabet(0))),
        ),
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": jws(b64(b"plain text"))}),
            NoQuery::PayloadNotJson(JsonTextError::of(
                &serde_json::from_slice::<serde_json::Value>(b"plain text").unwrap_err(),
            )),
        ),
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": jws(b64(br#"{"nonce":"x"}"#))}),
            NoQuery::PayloadHasNoDcqlQuery,
        ),
        // A signed request whose `request` is not even a string.
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": {"payload": "aGk"}}),
            NoQuery::NotACompactJws(CompactFault::NotString),
        ),
        (
            "openid4vp-v1-multisigned",
            serde_json::json!({"request": {"payload": "!!!"}}),
            NoQuery::PayloadNotBase64url(PayloadFault::Encoding(Base64Error::Alphabet(0))),
        ),
        // Present but not decodable is not the same as absent.
        (
            "openid4vp-v1-multisigned",
            serde_json::json!({"request": 42}),
            NoQuery::RequestNotAJwsOrObject,
        ),
        // A string is the `-signed` shape.
        (
            "openid4vp-v1-multisigned",
            serde_json::json!({"request": "aGVhZGVy.aGk.c2ln"}),
            NoQuery::ShapeDoesNotMatchProtocol,
        ),
        (
            "openid4vp-v1-multisigned",
            serde_json::json!({"request": null}),
            NoQuery::RequestNotAJwsOrObject,
        ),
        // A JWS JSON object with no payload is a malformed signed request.
        (
            "openid4vp-v1-multisigned",
            serde_json::json!({"request": {"signatures": []}}),
            NoQuery::JwsObjectHasNoPayload,
        ),
    ];
    for (protocol, data, expected) in cases {
        assert_eq!(
            UnverifiedRequest::read(protocol, &data),
            Err(expected.clone()),
            "for {protocol} {data}"
        );
        assert!(!expected.to_string().is_empty());
    }
}

/// A JWE has five segments, and its second is an encrypted key.
#[test]
fn a_jwe_is_not_mistaken_for_a_jws() {
    let jwe = format!(
        "{}.{}.{}.{}.{}",
        b64(br#"{"alg":"ECDH-ES","enc":"A256GCM"}"#),
        b64(b"encrypted-key"),
        b64(b"iv"),
        b64(b"ciphertext"),
        b64(b"tag")
    );
    assert_eq!(
        UnverifiedRequest::read("openid4vp-v1-signed", &serde_json::json!({"request": jwe})),
        Err(NoQuery::NotACompactJws(CompactFault::Segments))
    );
}

/// A `dcql_query` that is present but not DCQL is its own failure, not a
/// missing one.
#[test]
fn a_malformed_dcql_query_reports_the_parse_error() {
    let data = serde_json::json!({"response_type": "vp_token", "response_mode": "dc_api",
        "nonce": "n-1", "dcql_query": {"credentials": "not an array"}});
    assert_eq!(
        UnverifiedRequest::read("openid4vp-v1-unsigned", &data),
        Err(NoQuery::Malformed(QueryError::Form {
            member: Member::Credentials,
            fault: FormFault::WrongType,
        }))
    );
}

/// ISO 18013-7 carries a CBOR DeviceRequest, not DCQL. Declining is what lets
/// the caller try another protocol rather than failing the whole request.
#[test]
fn the_iso_mdoc_protocol_declines_rather_than_failing() {
    assert_eq!(
        UnverifiedRequest::read("org.iso.mdoc", &serde_json::json!({})),
        Err(NoQuery::NoParser)
    );
}

// --- the shape must match the label ----------------------------------------

/// A request labelled `-unsigned` that carries a JWS is not answered: the label
/// is what the wallet uses to decide whether to verify a signature.
#[test]
fn an_unsigned_label_does_not_accept_a_signed_payload() {
    let data = serde_json::json!({"request": compact_jws(&request_object())});
    assert_eq!(
        UnverifiedRequest::read("openid4vp-v1-unsigned", &data),
        Err(NoQuery::ShapeDoesNotMatchProtocol),
        "the reason should name the mismatch, not a missing key"
    );
    assert!(
        first_supported_request(&envelope("openid4vp-v1-unsigned", data), &siros_default).is_none()
    );
}

/// And the converse: a `-signed` label does not accept an inline query.
#[test]
fn a_signed_label_does_not_accept_an_inline_query() {
    let data: serde_json::Value = serde_json::from_str(&request_object()).expect("json");
    assert_eq!(
        UnverifiedRequest::read("openid4vp-v1-signed", &data),
        Err(NoQuery::ShapeDoesNotMatchProtocol)
    );
}

/// Each signed protocol takes its own serialization, not the other's.
#[test]
fn the_two_signed_protocols_do_not_accept_each_other_s_shape() {
    let compact = serde_json::json!({"request": compact_jws(&request_object())});
    let json = serde_json::json!({
        "request": {"payload": b64(multisigned_object().as_bytes()).to_string(),
            "signatures": [signature()]}
    });

    assert!(UnverifiedRequest::read("openid4vp-v1-signed", &compact).is_ok());
    assert!(UnverifiedRequest::read("openid4vp-v1-multisigned", &json).is_ok());

    assert_eq!(
        UnverifiedRequest::read("openid4vp-v1-multisigned", &compact),
        Err(NoQuery::ShapeDoesNotMatchProtocol),
        "a compact JWS is the -signed shape, not a wrong-typed value"
    );
    assert_eq!(
        UnverifiedRequest::read("openid4vp-v1-signed", &json),
        Err(NoQuery::NotACompactJws(CompactFault::NotString))
    );
}

/// A label outside OpenID4VP 1.0, A.1 is not a supported protocol, whatever its
/// data (P2): declaring a protocol is not opting into reading requests under it.
#[test]
fn an_unknown_openid4vp_protocol_id_is_not_read() {
    let inline: serde_json::Value = serde_json::from_str(&request_object()).expect("json");
    assert_eq!(
        UnverifiedRequest::read("org.example.vp-v1", &inline),
        Err(NoQuery::NoParser)
    );
    assert_eq!(
        UnverifiedRequest::read(
            "org.example.vp-v1",
            &serde_json::json!({"request": compact_jws(&request_object())})
        ),
        Err(NoQuery::NoParser)
    );
}

// --- negotiation -----------------------------------------------------------

/// A verifier offers the same request under several protocols, and the first
/// one that reads wins.
#[test]
fn an_unreadable_protocol_falls_through_to_a_readable_one() {
    let request = serde_json::json!({"requests": [
        {"protocol": "openid4vp-v1-signed", "data": {"request": "truncated"}},
        {"protocol": "openid4vp-v1-unsigned",
         "data": serde_json::from_str::<serde_json::Value>(&request_object()).expect("json")}
    ]})
    .to_string()
    .into_bytes();

    let (protocol, _) = first_supported_request(&request, &siros_default)
        .expect("should fall through to the unsigned entry");
    assert_eq!(protocol, "openid4vp-v1-unsigned");
}

/// A protocol the wallet did not register is skipped even when it is readable,
/// because which protocols are supported is a registration decision.
#[test]
fn a_protocol_outside_the_profile_is_skipped() {
    let data: serde_json::Value = serde_json::from_str(&request_object()).expect("json");
    assert!(first_supported_request(&envelope("org.iso.mdoc", data), &siros_default).is_none());
}

// --- diagnostics -----------------------------------------------------------

#[test]
fn the_diagnostic_names_the_signed_failure_rather_than_the_missing_key() {
    let profile = siros_default;
    let data = serde_json::json!({"request": jws("@@@@")});
    let text = diagnose(&envelope("openid4vp-v1-signed", data), &profile);
    assert!(text.contains("base64url"), "got: {text}");
    assert!(!text.contains("has no `dcql_query`"), "got: {text}");
}

#[test]
fn the_diagnostic_survives_every_malformed_envelope() {
    let profile = siros_default;
    for raw in [
        &b"not json"[..],
        b"{}",
        br#"{"requests": []}"#,
        br#"{"requests": [{}]}"#,
        br#"{"requests": [{"protocol": "openid4vp-v1-signed"}]}"#,
        br#"{"requests": [{"protocol": "nope", "data": {}}]}"#,
    ] {
        assert!(!diagnose(raw, &profile).is_empty(), "empty for {raw:?}");
    }
}

// --- the full request context ----------------------------------------------

fn two_entry_envelope(
    first: (&str, serde_json::Value),
    second: (&str, serde_json::Value),
) -> Vec<u8> {
    serde_json::json!({"requests": [
        {"protocol": first.0, "data": first.1},
        {"protocol": second.0, "data": second.1},
    ]})
    .to_string()
    .into_bytes()
}

fn unsigned_data() -> serde_json::Value {
    serde_json::from_str(&request_object()).expect("json")
}

fn signed_data() -> serde_json::Value {
    serde_json::json!({"request": compact_jws(&request_object())})
}

#[test]
fn an_unsigned_request_yields_its_full_context() {
    let ctx = first(
        &envelope("openid4vp-v1-unsigned", unsigned_data()),
        &siros_default,
    )
    .expect("context");
    assert_eq!(ctx.protocol().label(), "openid4vp-v1-unsigned");
    assert!(!ctx.protocol().is_signed());
    // A.2: the Wallet ignores the `client_id` and `expected_origins` of an unsigned request.
    assert_eq!(ctx.client_id(), None);
    assert_eq!(ctx.expected_origins(), None);
    assert_eq!(
        ctx.client_metadata(),
        Some(&serde_json::json!({"jwks": {"keys": []}}))
    );
    assert_eq!(ctx.query().credentials()[0].id(), "pid");
}

#[test]
fn a_signed_request_yields_its_full_context() {
    let ctx = first(
        &envelope("openid4vp-v1-signed", signed_data()),
        &siros_default,
    )
    .expect("context");
    assert_eq!(ctx.protocol().label(), "openid4vp-v1-signed");
    assert!(ctx.protocol().is_signed());
    assert_eq!(
        ctx.client_id().map(ClientId::as_str),
        Some("x509_san_dns:verifier.example")
    );
    assert_eq!(
        ctx.expected_origins(),
        Some(["https://verifier.example".to_owned()].as_slice())
    );
    assert!(ctx.client_metadata().is_some());
    assert_eq!(ctx.query().credentials()[0].id(), "pid");
}

/// The rulebook v0.4 example puts an object under `claims`: DCQL refuses the request, a `zkp_req`
/// query's among them.
#[test]
fn object_claims_are_malformed_in_every_format() {
    for format in ["zkp_req", "mso_mdoc"] {
        let data = serde_json::json!({"response_type": "vp_token", "response_mode": "dc_api",
            "nonce": "n-1", "dcql_query": {"credentials": [{
            "id": "nym", "format": format,
            "meta": {"doctype_value": "eu.europa.ec.eudi.nym_auth.1"},
            "claims": {"_req": [{"fn_id": "age_check", "params": {"ge": "2008-10-10"}}]}
        }]}});
        assert!(first(
            &envelope("openid4vp-v1-unsigned", data.clone()),
            &siros_default
        )
        .is_none());
        assert_eq!(
            UnverifiedRequest::read("openid4vp-v1-unsigned", &data),
            Err(NoQuery::Malformed(QueryError::Form {
                member: Member::CredentialMember(Position::new(0), CredentialMember::Claims),
                fault: FormFault::WrongType,
            })),
            "{format}"
        );
    }
}

#[test]
fn a_predicate_can_skip_an_unsigned_first_entry_for_a_signed_second() {
    let bytes = two_entry_envelope(
        ("openid4vp-v1-unsigned", unsigned_data()),
        ("openid4vp-v1-signed", signed_data()),
    );
    let profile = siros_default;
    let no_unsigned = |label: &str| profile(label) && label != "openid4vp-v1-unsigned";
    let ctx = first(&bytes, &no_unsigned).expect("context");
    assert_eq!(ctx.protocol().label(), "openid4vp-v1-signed");
    assert!(ctx.protocol().is_signed());

    // The whole registration: the first supported entry wins.
    let first = first(&bytes, &profile).expect("context");
    assert_eq!(first.protocol().label(), "openid4vp-v1-unsigned");
}

#[test]
fn a_predicate_that_rejects_everything_yields_no_context() {
    let bytes = two_entry_envelope(
        ("openid4vp-v1-unsigned", unsigned_data()),
        ("openid4vp-v1-signed", signed_data()),
    );
    let reject_all = |_: &str| false;
    assert!(first(&bytes, &reject_all).is_none());
}

#[test]
fn an_unknown_protocol_still_yields_no_context() {
    assert!(first(
        &envelope("some-other-protocol", unsigned_data()),
        &siros_default
    )
    .is_none());
}
