//! The refusals of S1 (RFC 9901 §7.1): one fixture per rule.

use siros_openid4vp::json::JsonError;
use siros_sdjwt::{
    Digest, DisclosureFault, DisclosureId, EncodedJsonFault, IssuerJwtFault, Misplaced, ParseError,
    ReservedFault, SdAlgFault, SdJwt,
};

use crate::common::{compact, decoy, disclosure};

#[test]
fn s1_refusals() {
    let (property, property_digest) = disclosure(r#"["2GLC42sKQveCfGfryNRN9w","a",1]"#);
    let (element, element_digest) = disclosure(r#"["eluV5Og3gSNII8EYnsxA_A",1]"#);
    let (reserved, reserved_digest) = disclosure(r#"["6Ij7tM-a5iVPGboS5tmvVA","_sd",1]"#);
    let (taken, taken_digest) = disclosure(r#"["eI8ZWm9QnKPpNPeNenHdhQ","given_name","b"]"#);
    let (four, _) = disclosure(r#"["Qg_O64zqAxe412a108iroA","a",1,2]"#);
    let x = decoy("x");
    let deep = format!(r#"{{"a":{}{}}}"#, "[".repeat(40), "]".repeat(40));

    let first = DisclosureId::new(0);
    let reserved_name = ParseError::ReservedClaimName;
    let rows: Vec<(&str, ParseError, String)> = vec![
        (
            "a repeated payload member",
            ParseError::IssuerJwt(IssuerJwtFault::Payload(EncodedJsonFault::Json(
                JsonError::DuplicateMember("a".to_owned()),
            ))),
            compact(r#"{"a":1,"a":2}"#, &[]),
        ),
        (
            "an issuer JWT without a signature",
            ParseError::IssuerJwt(IssuerJwtFault::Segments(2)),
            "eyJhbGciOiJFUzI1NiJ9.e30~".to_owned(),
        ),
        (
            "a disclosure of four elements",
            ParseError::Disclosure {
                disclosure: first,
                fault: DisclosureFault::Length(4),
            },
            compact("{}", &[&four]),
        ),
        (
            "a truncated digest",
            ParseError::UnsupportedSdAlg(SdAlgFault::Unknown("sha-256-32".to_owned())),
            compact(r#"{"_sd_alg":"sha-256-32"}"#, &[]),
        ),
        (
            "a disclosure named _sd",
            reserved_name(ReservedFault::Disclosed("_sd".to_owned())),
            compact(&format!(r#"{{"_sd":["{reserved_digest}"]}}"#), &[&reserved]),
        ),
        (
            "an object member named ...",
            reserved_name(ReservedFault::Ellipsis),
            compact(&format!(r#"{{"a":{{"...":"{x}"}}}}"#), &[]),
        ),
        (
            "a nested _sd_alg",
            reserved_name(ReservedFault::NestedSdAlg),
            compact(r#"{"a":{"_sd_alg":"sha-256"}}"#, &[]),
        ),
        (
            "an _sd holding a number",
            reserved_name(ReservedFault::SdDigest),
            compact(r#"{"_sd":[1]}"#, &[]),
        ),
        (
            "an array digest beside another member",
            reserved_name(ReservedFault::ElementMembers),
            compact(&format!(r#"{{"a":[{{"...":"{x}","b":1}}]}}"#), &[]),
        ),
        (
            "a decoy twice",
            ParseError::RepeatedDigest(Digest::new(&x)),
            compact(&format!(r#"{{"_sd":["{x}","{x}"]}}"#), &[]),
        ),
        (
            "a disclosure twice",
            ParseError::RepeatedDigest(Digest::new(&property_digest)),
            compact(
                &format!(r#"{{"_sd":["{property_digest}"]}}"#),
                &[&property, &property],
            ),
        ),
        (
            "an element disclosure in _sd",
            ParseError::MisplacedDisclosure {
                disclosure: first,
                placement: Misplaced::ElementInObject,
            },
            compact(&format!(r#"{{"_sd":["{element_digest}"]}}"#), &[&element]),
        ),
        (
            "a property disclosure in an array",
            ParseError::MisplacedDisclosure {
                disclosure: first,
                placement: Misplaced::PropertyInArray,
            },
            compact(
                &format!(r#"{{"a":[{{"...":"{property_digest}"}}]}}"#),
                &[&property],
            ),
        ),
        (
            "a disclosure of a permanent claim's name",
            ParseError::ClaimNameExists("given_name".to_owned()),
            compact(
                &format!(r#"{{"given_name":"a","_sd":["{taken_digest}"]}}"#),
                &[&taken],
            ),
        ),
        (
            "a disclosure no digest names",
            ParseError::UnreferencedDisclosure(first),
            compact("{}", &[&property]),
        ),
        (
            "41 levels of arrays",
            ParseError::TooDeep,
            compact(&deep, &[]),
        ),
    ];
    for (case, cause, sd_jwt) in rows {
        match SdJwt::parse(&sd_jwt) {
            Ok(_) => panic!("{case}: accepted"),
            Err(e) => assert_eq!(e, cause, "{case}"),
        }
    }
}
