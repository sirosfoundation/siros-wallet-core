//! Disclosure selection (S3), issued array positions (S2) and the KB-JWT claims (S4).

use serde_json::{json, Value};
use siros_codec::base64url;
use siros_codec::date::DateTime;
use siros_dcql::ClaimPath;
use siros_sdjwt::{Audience, ClaimValue, Element, KbNonce, KeyBindingError, NumericDate, SdJwt};

use crate::common::{compact, decoy, disclosure, issued};

/// The disclosures of a presentation, each as `name`, `name=value` for a scalar, or `[value]`
/// for an array element.
fn labels(presentation: &str) -> Vec<String> {
    let parts: Vec<&str> = presentation.split('~').collect();
    parts[1..parts.len() - 1]
        .iter()
        .map(|d| {
            let array: Value = serde_json::from_slice(&base64url::decode(d).unwrap()).unwrap();
            match array.as_array().unwrap().as_slice() {
                [_, Value::String(name), value] if value.is_object() || value.is_array() => {
                    name.clone()
                }
                [_, Value::String(name), value] => format!("{name}={value}"),
                [_, value] => format!("[{value}]"),
                _ => panic!("not a disclosure: {d}"),
            }
        })
        .collect()
}

fn outcome(sd_jwt: &SdJwt, pointers: &str) -> Result<Vec<String>, &'static str> {
    let pointers: Vec<ClaimPath> = serde_json::from_str(pointers).unwrap();
    sd_jwt
        .select(&pointers)
        .map(|p| labels(p.as_str()))
        .map_err(|e| e.code())
}

/// The RFC 9901, Appendix A.3 credential: `address` and `place_of_birth` are disclosures whose
/// values hold disclosures; `nationalities` is a disclosure of the plain array `["DE"]`. The
/// expected disclosures are read off the example's listing.
#[test]
fn selection() {
    let a3 = SdJwt::parse(&issued("a3")).unwrap();
    let rows: [(&str, Result<&[&str], &str>); 7] = [
        ("[]", Ok(&[])),
        (
            r#"[["place_of_birth", "locality"]]"#,
            Ok(&["place_of_birth", r#"locality="Berlin""#]),
        ),
        (
            r#"[["address"]]"#,
            Ok(&[
                "address",
                r#"street_address="Heidestraße 17""#,
                r#"locality="Köln""#,
                r#"country="DE""#,
                r#"postal_code="51147""#,
            ]),
        ),
        (
            r#"[["address", "locality"], ["address"]]"#,
            Ok(&[
                "address",
                r#"locality="Köln""#,
                r#"street_address="Heidestraße 17""#,
                r#"country="DE""#,
                r#"postal_code="51147""#,
            ]),
        ),
        (r#"[["nationalities", null]]"#, Ok(&["nationalities"])),
        (r#"[["address", 0]]"#, Err("path_type_mismatch")),
        (r#"[["birth_middle_name"]]"#, Err("path_selects_nothing")),
    ];
    for (pointers, expected) in rows {
        let expected = expected.map(|labels| labels.iter().map(|l| l.to_string()).collect());
        assert_eq!(outcome(&a3, pointers), expected, "{pointers}");
    }
}

/// `["DE", decoy, FR]`: the decoy is a withheld element at position 1, and FR stays at 2.
#[test]
fn decoy_keeps_array_positions() {
    let (fr, fr_digest) = disclosure(&json!(["lklxF5jMYlGTPUovMNIvCA", "FR"]));
    let payload = json!({"nationalities": ["DE", {"...": decoy("decoy")}, {"...": fr_digest}]});
    let sd_jwt = SdJwt::parse(&compact(&payload.to_string(), &[&fr])).unwrap();

    let Some(ClaimValue::Array(elements)) = sd_jwt.claims().get("nationalities").map(|c| c.value())
    else {
        panic!("nationalities is not an array");
    };
    let positions: Vec<(Option<&str>, bool)> = elements
        .iter()
        .map(|e| match e {
            Element::Present(claim) => match claim.value() {
                ClaimValue::String(s) => (Some(s.as_str()), claim.disclosure().is_some()),
                _ => panic!("not a string"),
            },
            Element::Withheld => (None, false),
        })
        .collect();
    assert_eq!(
        positions,
        [(Some("DE"), false), (None, false), (Some("FR"), true)]
    );

    let rows: [(&str, Result<&[&str], &str>); 4] = [
        (r#"[["nationalities", 0]]"#, Ok(&[])),
        (r#"[["nationalities", 1]]"#, Err("path_selects_nothing")),
        (r#"[["nationalities", 2]]"#, Ok(&[r#"["FR"]"#])),
        (r#"[["nationalities", null]]"#, Ok(&[r#"["FR"]"#])),
    ];
    for (pointers, expected) in rows {
        let expected = expected.map(|labels| labels.iter().map(|l| l.to_string()).collect());
        assert_eq!(outcome(&sd_jwt, pointers), expected, "{pointers}");
    }
}

type Claims = Vec<(String, Value)>;

/// Extra claims follow the four Section 4.3 requires; a repeated name is refused. The accepted
/// row is the KB-JWT payload example of OpenID4VP 1.0, Appendix B.3.6, whose `sd_hash` covers
/// another presentation and is left out of the comparison.
#[test]
fn key_binding_claims() {
    let a3 = SdJwt::parse(&issued("a3")).unwrap();
    let hashes = json!(["fOBUSQvo46yQO-wRwXBcGqvnbKIueISEL961_Sjd4do"]);
    let rows: [(Claims, Result<(), KeyBindingError>); 3] = [
        (vec![("transaction_data_hashes".into(), hashes)], Ok(())),
        (
            vec![("nonce".into(), json!("n-0S6_WzA2Mj"))],
            Err(KeyBindingError::RequiredClaim("nonce".to_owned())),
        ),
        (
            vec![("jti".into(), json!("a")), ("jti".into(), json!("b"))],
            Err(KeyBindingError::RepeatedClaim("jti".to_owned())),
        ),
    ];
    let iat = NumericDate::of(DateTime::from_unix(1709838604).unwrap()).unwrap();
    let aud = Audience::new("x509_san_dns:client.example.org");
    let nonce = KbNonce::new("n-0S6_WzA2Mj");
    for (extra, expected) in rows {
        let presentation = a3.select(&[]).unwrap();
        let binding = presentation.key_binding(iat, &aud, &nonce, &extra);
        let binding = match (binding, expected) {
            (Ok(binding), Ok(())) => binding,
            (Err(e), Err(cause)) => {
                assert_eq!(e.code(), "kb_jwt_claim_collision");
                assert_eq!(e, cause);
                continue;
            }
            (Ok(_), Err(cause)) => panic!("accepted, expected {cause}"),
            (Err(e), Ok(())) => panic!("refused: {e}"),
        };
        let input = std::str::from_utf8(binding.signing_input()).unwrap();
        let (_, payload) = input.split_once('.').unwrap();
        let mut payload: Value =
            serde_json::from_slice(&base64url::decode(payload).unwrap()).unwrap();
        assert!(payload.as_object_mut().unwrap().remove("sd_hash").is_some());
        assert_eq!(
            payload,
            json!({
                "nonce": "n-0S6_WzA2Mj",
                "aud": "x509_san_dns:client.example.org",
                "iat": 1709838604,
                "transaction_data_hashes": ["fOBUSQvo46yQO-wRwXBcGqvnbKIueISEL961_Sjd4do"]
            })
        );
    }
}
