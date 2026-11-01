//! Where the Verifier metadata of a request the credential picker reads comes from.

use siros_codec::base64url::encode as b64;
use siros_oid4vp::{NoQuery, ParameterFault, UnverifiedRequest};

/// A request object whose `client_metadata` is a string.
fn request_object() -> String {
    serde_json::json!({
        "response_type": "vp_token",
        "response_mode": "dc_api.jwt",
        "nonce": "n-0S6_WzA2Mj",
        "expected_origins": ["https://verifier.example"],
        "dcql_query": {"credentials": [{
            "id": "pid", "format": "mso_mdoc",
            "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
            "claims": [{"path": ["org.iso.18013.5.1", "age_over_18"]}]
        }]}
    })
    .to_string()
}

/// A compact JWS of `payload` whose header and signature keep the rules the picker reads.
fn compact_jws(payload: &str) -> String {
    let header = br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#;
    format!(
        "{}.{}.{}",
        b64(header),
        b64(payload.as_bytes()),
        signature()
    )
}

/// 64 bytes in place of an ES256 signature, which the picker never verifies.
fn signature() -> String {
    b64(&[7; 64]).to_string()
}

/// The Verifier metadata of a request comes from its `client_metadata`, which is then a JSON
/// object, except for an `openid_federation` client, whose Trust Chain carries it (Section
/// 5.9.3): a signed request's client, or one a multisigned request's protected header names.
#[test]
fn client_metadata_is_the_requests_except_for_a_federation_client() {
    let object = |client_id: Option<&str>| {
        let mut object: serde_json::Value = serde_json::from_str(&request_object()).expect("json");
        object["client_metadata"] = serde_json::json!("x");
        match client_id {
            Some(client_id) => object["client_id"] = serde_json::json!(client_id),
            None => drop(object.as_object_mut().expect("object").remove("client_id")),
        }
        object.to_string()
    };
    let signed = |client_id: &str| {
        let data = serde_json::json!({"request": compact_jws(&object(Some(client_id)))});
        UnverifiedRequest::read("openid4vp-v1-signed", &data)
    };
    let multisigned = |client_id: &str| {
        let header = serde_json::json!({"alg": "ES256", "typ": "oauth-authz-req+jwt",
            "client_id": client_id});
        let data = serde_json::json!({
            "payload": b64(object(None).as_bytes()).to_string(),
            "signatures": [{"protected": b64(header.to_string().as_bytes()).to_string(),
                "signature": signature()}]
        });
        UnverifiedRequest::read("openid4vp-v1-multisigned", &data)
    };
    let refused = Err(NoQuery::Parameter(ParameterFault::ClientMetadataInvalid));
    assert_eq!(signed("x509_san_dns:verifier.example").map(drop), refused);
    assert_eq!(
        multisigned("x509_san_dns:verifier.example").map(drop),
        refused
    );
    let federation = "openid_federation:https://verifier.example";
    for read in [signed(federation), multisigned(federation)] {
        assert_eq!(read.expect("read").client_metadata(), None);
    }
}
