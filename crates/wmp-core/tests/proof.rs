//! PR #46: the DPoP proof omits `sid` only on `session.create`; it is
//! mandatory (and exact) on every other request.

use wmp_core::proof::{AuthScheme, ParsedAuth, ProofPayload};

fn payload(sid: Option<&str>) -> ProofPayload {
    ProofPayload {
        htm: "POST".to_owned(),
        htu: "https://relay.example.com/wmp".to_owned(),
        iat: 1_795_526_400,
        jti: "proof-1".to_owned(),
        sid: sid.map(str::to_owned),
    }
}

#[test]
fn session_create_omits_sid_from_the_canonical_payload() {
    let payload = ProofPayload::for_session_create(
        "POST",
        "https://relay.example.com/wmp",
        1_795_526_400,
        "proof-1",
    );
    let json = String::from_utf8(payload.canonical_bytes().expect("canonical bytes")).unwrap();
    assert!(
        !json.contains("\"sid\""),
        "the create proof carries no sid: {json}"
    );
    assert!(json.starts_with(
        "{\"htm\":\"POST\",\"htu\":\"https://relay.example.com/wmp\",\"iat\":1795526400"
    ));
    assert!(
        payload.session_binding_matches(None, true),
        "sid is optional on session.create"
    );
}

#[test]
fn other_requests_require_and_match_the_session_id() {
    let bound = payload(Some("ses-a1b2c3d4"));
    assert!(bound.session_binding_matches(Some("ses-a1b2c3d4"), false));
    assert!(!bound.session_binding_matches(Some("ses-other"), false));
    assert!(
        !bound.session_binding_matches(None, false),
        "a non-create request MUST carry sid"
    );

    let no_sid = payload(None);
    assert!(
        !no_sid.session_binding_matches(Some("ses-a1b2c3d4"), false),
        "absent sid is refused off-create"
    );
}

#[test]
fn dpop_and_bearer_parse_independently() {
    let dpop = ParsedAuth::parse("DPoP header.payload.signature").expect("DPoP");
    assert_eq!(dpop.scheme, AuthScheme::Dpop);
    assert_eq!(dpop.credential, "header.payload.signature");

    let bearer = ParsedAuth::parse("Bearer abc.def.ghi").expect("Bearer");
    assert_eq!(bearer.scheme, AuthScheme::Bearer);
    assert_eq!(bearer.credential, "abc.def.ghi");

    assert!(ParsedAuth::parse("Basic abc").is_none());
}
