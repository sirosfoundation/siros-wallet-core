//! A request's arrival over the DC API (A.1 to A.3) and the JOSE it arrives in (RFC 7515 §7,
//! RFC 7516 §7.1): one fixture per U rule these steps own and per parsing entry point, each
//! asserting the rule's variant and the member its text names; and the digest's domains.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_openid4vp::arrival::{
    DataShape, DcApiProtocol, DcApiProtocols, FailedStatus, Received, Unreadable,
};
use siros_openid4vp::host::{NotPresentation, Presentation};
use siros_openid4vp::ids::Origin;
use siros_openid4vp::jose::{CompactJwe, JsonJws, JweError, JwsError, NotPublicJwk, PublicJwk};
use siros_openid4vp::json::{JsonError, Node};
use siros_testkit::jose::DECRYPTS;

const ORIGIN: &str = "https://verifier.example";
const PARAMETERS: &str = r#"{"response_type":"vp_token","nonce":"n"}"#;

fn b64(text: &str) -> String {
    URL_SAFE_NO_PAD.encode(text)
}

/// A compact JWS of a header and a payload, as written, with a 64-octet signature.
fn compact(header: &str, payload: &str) -> String {
    format!(
        "{}.{}.{}",
        b64(header),
        b64(payload),
        URL_SAFE_NO_PAD.encode([7u8; 64])
    )
}

const HEADER: &str = r#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#;

fn dc_api<'a>(
    protocol: &str,
    data: &'a str,
    protocols: &DcApiProtocols,
) -> Result<Received<'a>, Unreadable> {
    Received::dc_api(
        protocol,
        data,
        Origin::parse(ORIGIN).expect("origin"),
        protocols,
    )
}

fn refused(protocol: &str, data: &str) -> Unreadable {
    dc_api(protocol, data, &DcApiProtocols::ALL).expect_err(data)
}

#[test]
fn a_dc_api_request_names_a_registered_protocol_of_a_1() {
    assert_eq!(
        refused("openid4vp-v2-unsigned", PARAMETERS),
        Unreadable::Protocol {
            protocol: "openid4vp-v2-unsigned".to_owned()
        }
    );
    // The WE BUILD build registers the signed protocols alone (CS-07 WU-DC-01).
    assert_eq!(
        dc_api("openid4vp-v1-unsigned", PARAMETERS, &DcApiProtocols::SIGNED).map(drop),
        Err(Unreadable::Unregistered {
            protocol: DcApiProtocol::Unsigned
        })
    );
    let signed = format!(r#"{{"request":"{}"}}"#, compact(HEADER, PARAMETERS));
    assert!(dc_api("openid4vp-v1-signed", &signed, &DcApiProtocols::SIGNED).is_ok());
    // A build without `signed` registers the unsigned protocol alone.
    assert_eq!(
        dc_api("openid4vp-v1-signed", &signed, &DcApiProtocols::UNSIGNED).map(drop),
        Err(Unreadable::Unregistered {
            protocol: DcApiProtocol::Signed
        })
    );
}

#[test]
fn data_has_its_protocols_shape() {
    // U2: signed `data` without `request`, or `request` no string.
    for data in [r#"{"jws":"a.b.c"}"#, r#"{"request":5}"#] {
        assert_eq!(
            refused("openid4vp-v1-signed", data),
            Unreadable::Shape {
                protocol: DcApiProtocol::Signed,
                cause: DataShape::Request
            }
        );
    }
    assert!(matches!(
        refused("openid4vp-v1-signed", "[1]"),
        Unreadable::Shape {
            protocol: DcApiProtocol::Signed,
            cause: DataShape::Json(_)
        }
    ));
    // U3: unsigned parameters with a member named twice, at the top or deeper.
    for (data, member) in [
        (r#"{"nonce":"a","nonce":"b"}"#, "nonce"),
        (r#"{"nonce":"a","dcql_query":{"x":1,"x":2}}"#, "x"),
    ] {
        assert_eq!(
            refused("openid4vp-v1-unsigned", data),
            Unreadable::Json(JsonError::DuplicateMember {
                member: member.to_owned()
            })
        );
    }
}

/// The JWS of a signed DC API request.
fn signed(jws: &str) -> Unreadable {
    refused("openid4vp-v1-signed", &format!(r#"{{"request":"{jws}"}}"#))
}

#[test]
fn a_compact_jws_names_its_alg_in_three_base64url_parts() {
    let payload = b64(PARAMETERS);
    let signature = URL_SAFE_NO_PAD.encode([7u8; 64]);
    let cases = [
        // Structure: two parts.
        (format!("{}.{payload}", b64(HEADER)), JwsError::Structure),
        // base64: a part no base64url, and one with padding.
        (
            format!("{}.{payload}.{signature}=", b64(HEADER)),
            JwsError::Base64,
        ),
        (
            format!("{}.{payload}.{signature}", b64(HEADER).replace('e', "*")),
            JwsError::Base64,
        ),
        // The json module under JOSE: a header member twice.
        (
            compact(r#"{"alg":"ES256","kid":"a","kid":"b"}"#, PARAMETERS),
            JwsError::Json(JsonError::DuplicateMember {
                member: "kid".to_owned(),
            }),
        ),
        // An alg that is none (RFC 8725 §3.2), absent, no string, or no registry name.
        (
            compact(r#"{"alg":"none"}"#, PARAMETERS),
            JwsError::Algorithm {
                alg: Some("none".to_owned()),
            },
        ),
        (
            compact(r#"{"typ":"JWT"}"#, PARAMETERS),
            JwsError::Algorithm { alg: None },
        ),
        (
            compact(r#"{"alg":7}"#, PARAMETERS),
            JwsError::Algorithm {
                alg: Some("7".to_owned()),
            },
        ),
        (
            compact(r#"{"alg":"ES 256"}"#, PARAMETERS),
            JwsError::Algorithm {
                alg: Some("ES 256".to_owned()),
            },
        ),
        // A kid of another kind than string (RFC 7515 §4.1.4).
        (
            compact(r#"{"alg":"ES256","kid":7}"#, PARAMETERS),
            JwsError::Member { member: "kid" },
        ),
        // U16: crit naming a header, and crit empty.
        (
            compact(r#"{"alg":"ES256","crit":["exp"],"exp":1}"#, PARAMETERS),
            JwsError::Critical {
                header: "exp".to_owned(),
            },
        ),
        (
            compact(r#"{"alg":"ES256","crit":[]}"#, PARAMETERS),
            JwsError::Critical {
                header: "[]".to_owned(),
            },
        ),
    ];
    for (jws, error) in cases {
        assert_eq!(signed(&jws), Unreadable::Jws(error), "{jws}");
    }
}

/// A JWS JSON Serialization of signature objects over the parameters.
fn general(signatures: &[String]) -> String {
    format!(
        r#"{{"payload":"{}","signatures":[{}]}}"#,
        b64(PARAMETERS),
        signatures.join(",")
    )
}

fn signature(protected: &str, unprotected: Option<&str>) -> String {
    let header = unprotected.map_or_else(String::new, |header| format!(r#","header":{header}"#));
    format!(
        r#"{{"protected":"{}"{header},"signature":"{}"}}"#,
        b64(protected),
        URL_SAFE_NO_PAD.encode([7u8; 64])
    )
}

#[test]
fn a_jws_json_serialization_keeps_each_name_once_and_its_headers_disjoint() {
    let good = signature(HEADER, Some(r#"{"kid":"k"}"#));
    // Both forms of A.3.2.2 read: `data.request` and `data` itself (reading 5).
    let bare = general(&[good.clone(), good.clone()]);
    let jws = JsonJws::parse(bare.as_str()).expect("general");
    assert_eq!((jws.payload(), jws.signatures().count()), (PARAMETERS, 2));
    assert!(dc_api("openid4vp-v1-multisigned", &bare, &DcApiProtocols::ALL).is_ok());
    let wrapped = format!(
        r#"{{"request":{}}}"#,
        serde_json::to_string(&bare).expect("json")
    );
    assert!(dc_api("openid4vp-v1-multisigned", &wrapped, &DcApiProtocols::ALL).is_ok());
    let flattened = format!(
        r#"{{"payload":"{}","protected":"{}","signature":"{}"}}"#,
        b64(PARAMETERS),
        b64(HEADER),
        URL_SAFE_NO_PAD.encode([7u8; 64])
    );
    assert_eq!(
        JsonJws::parse(flattened.as_str())
            .expect("flattened")
            .signatures()
            .count(),
        1
    );
    let twice = |member: &str| {
        JwsError::Json(JsonError::DuplicateMember {
            member: member.to_owned(),
        })
    };
    let cases = [
        // A member of the serialization twice.
        (
            format!(
                r#"{{"payload":"{0}","payload":"{0}","signatures":[{good}]}}"#,
                b64(PARAMETERS)
            ),
            twice("payload"),
        ),
        // A signature object's member twice.
        (
            general(&[good.replacen(r#""signature""#, r#""protected":"x","signature""#, 1)]),
            twice("protected"),
        ),
        // An unprotected header's member twice.
        (
            general(&[signature(HEADER, Some(r#"{"kid":"a","kid":"b"}"#))]),
            twice("kid"),
        ),
        // RFC 7515 §7.2.1: one name in both headers.
        (
            general(&[signature(HEADER, Some(r#"{"typ":"JWT"}"#))]),
            JwsError::HeaderTwice {
                header: "typ".to_owned(),
            },
        ),
        // An empty signatures array.
        (general(&[]), JwsError::Structure),
        // crit in an unprotected header.
        (
            general(&[signature(HEADER, Some(r#"{"crit":["b64"]}"#))]),
            JwsError::Critical {
                header: "crit".to_owned(),
            },
        ),
    ];
    for (jws, error) in cases {
        assert_eq!(
            refused("openid4vp-v1-multisigned", &jws),
            Unreadable::Jws(error),
            "{jws}"
        );
    }
}

#[test]
fn a_jwe_request_object_names_an_alg_and_enc_the_module_decrypts() {
    let jwe = |header: &str| {
        format!(
            "{}..{}.{}.{}",
            b64(header),
            b64("iv"),
            b64("ct"),
            b64("tag")
        )
    };
    let ok = jwe(r#"{"alg":"ECDH-ES","enc":"A128GCM","epk":{}}"#);
    assert!(CompactJwe::parse(&ok, &DECRYPTS).is_ok());
    let cases = [
        ("a.b.c".to_owned(), JweError::Structure),
        (format!("{ok}="), JweError::Base64),
        (
            jwe(r#"{"alg":"RSA-OAEP","enc":"A128GCM"}"#),
            JweError::Algorithm {
                alg: Some("RSA-OAEP".to_owned()),
            },
        ),
        (
            jwe(r#"{"alg":"ECDH-ES","enc":"A128CBC-HS256"}"#),
            JweError::Encryption {
                enc: Some("A128CBC-HS256".to_owned()),
            },
        ),
        (
            jwe(r#"{"alg":"ECDH-ES","enc":"A256GCM","crit":["zip"]}"#),
            JweError::Critical {
                header: r#"["zip"]"#.to_owned(),
            },
        ),
        (
            jwe(r#"{"alg":"ECDH-ES","alg":"ECDH-ES","enc":"A128GCM"}"#),
            JweError::Json(JsonError::DuplicateMember {
                member: "alg".to_owned(),
            }),
        ),
    ];
    for (text, error) in cases {
        assert_eq!(
            CompactJwe::parse(&text, &DECRYPTS).map(drop),
            Err(error),
            "{text}"
        );
    }
}

#[test]
fn constructors_refuse_what_their_rule_excludes() {
    assert_eq!(FailedStatus::new(200), None);
    assert_eq!(FailedStatus::new(99), None);
    assert_eq!(FailedStatus::new(404).map(FailedStatus::code), Some(404));
    // RFC 7517 §4.1 and RFC 7518 §6.2.2, §6.3.2, §6.4: a public JWK names its kty and holds no
    // private member.
    let jwk = |text: &str| PublicJwk::parse(Node::parse(text).expect("json")).map(drop);
    assert_eq!(
        jwk(r#"{"kty":"EC","crv":"P-256","x":"AA","y":"AQ"}"#),
        Ok(())
    );
    assert_eq!(jwk(r#"["EC"]"#), Err(NotPublicJwk::Object));
    assert_eq!(jwk(r#"{"crv":"P-256"}"#), Err(NotPublicJwk::KeyType));
    assert_eq!(
        jwk(r#"{"kty":"EC","crv":"P-256","x":"AA","y":"AQ","d":"AA"}"#),
        Err(NotPublicJwk::Private {
            member: "d".to_owned()
        })
    );
    assert_eq!(
        jwk(r#"{"kty":"oct","k":"AA"}"#),
        Err(NotPublicJwk::Private {
            member: "k".to_owned()
        })
    );
    // §8.1: a presentation is "a string or a JSON object".
    assert_eq!(
        Presentation::text("eyJ0.e30.c2ln~").as_str(),
        r#""eyJ0.e30.c2ln~""#
    );
    let object = r#"{"proof": {"nonce": "n"}}"#;
    assert_eq!(
        Presentation::object(object).map(|p| p.as_str().to_owned()),
        Ok(object.to_owned())
    );
    for refused in [r#""eyJ0.e30.c2ln~""#, "[1]", r#"{"a": 1, "a": 2}"#] {
        assert_eq!(
            Presentation::object(refused),
            Err(NotPresentation),
            "{refused}"
        );
    }
}

#[test]
fn digests_keep_todays_dc_api_rows_and_separate_the_forms() {
    use sha2::{Digest, Sha256};
    // The digest table's rows, computed here from the formula: length-prefixed parts.
    let digest = |parts: &[&[u8]]| {
        let mut hash = Sha256::new();
        for part in parts {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        URL_SAFE_NO_PAD.encode(hash.finalize())
    };
    let unsigned =
        dc_api("openid4vp-v1-unsigned", PARAMETERS, &DcApiProtocols::ALL).expect("unsigned");
    assert_eq!(
        unsigned.digest().as_str(),
        digest(&[ORIGIN.as_bytes(), &[0], PARAMETERS.as_bytes()])
    );
    let jws = compact(HEADER, PARAMETERS);
    let data = format!(r#"{{"request":"{jws}"}}"#);
    let signed = dc_api("openid4vp-v1-signed", &data, &DcApiProtocols::ALL).expect("signed");
    assert_eq!(
        signed.digest().as_str(),
        digest(&[
            ORIGIN.as_bytes(),
            &[1],
            jws.as_bytes(),
            PARAMETERS.as_bytes()
        ])
    );
    let multi = general(&[signature(HEADER, None)]);
    let multisigned =
        dc_api("openid4vp-v1-multisigned", &multi, &DcApiProtocols::ALL).expect("multisigned");
    assert_eq!(
        multisigned.digest().as_str(),
        digest(&[
            ORIGIN.as_bytes(),
            &[2],
            multi.as_bytes(),
            PARAMETERS.as_bytes()
        ])
    );
}
