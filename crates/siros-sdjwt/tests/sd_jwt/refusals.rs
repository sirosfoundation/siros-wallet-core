//! The refusals of S1: one fixture per rule and per place the rule is checked.

use serde_json::json;
use siros_codec::json::{JsonFault, JsonTextFault, ReadFault};
use siros_sdjwt::{
    Digest, DisclosureFault, DisclosureId, EncodedJsonFault, IssuerJwtFault, ParseError, Placement,
    ReservedFault, SdAlgFault, SdJwt,
};

use crate::common::{compact, decoy, disclosure};

#[test]
fn s1_refusals() {
    let (property, property_digest) = disclosure(&json!(["2GLC42sKQveCfGfryNRN9w", "a", 1]));
    let (element, element_digest) = disclosure(&json!(["eluV5Og3gSNII8EYnsxA_A", 1]));
    let (reserved, reserved_digest) = disclosure(&json!(["6Ij7tM-a5iVPGboS5tmvVA", "_sd", 1]));
    let (taken, taken_digest) = disclosure(&json!(["eI8ZWm9QnKPpNPeNenHdhQ", "given_name", "b"]));
    let (four, _) = disclosure(&json!(["Qg_O64zqAxe412a108iroA", "a", 1, 2]));
    let x = decoy("x");
    let deep = format!(r#"{{"a":{}{}}}"#, "[".repeat(40), "]".repeat(40));

    let first = DisclosureId::new(0);
    let reserved_name = |fault| ParseError::ReservedClaimName(fault);
    let rows: Vec<(&str, &str, ParseError, String)> = vec![
        (
            "a repeated payload member",
            "issuer_jwt_malformed",
            ParseError::IssuerJwt(IssuerJwtFault::Payload(EncodedJsonFault::Json(
                JsonFault::RepeatedMember("a".to_owned()),
            ))),
            compact(r#"{"a":1,"a":2}"#, &[]),
        ),
        (
            "an issuer JWT without a signature",
            "issuer_jwt_malformed",
            ParseError::IssuerJwt(IssuerJwtFault::Segments(2)),
            "eyJhbGciOiJFUzI1NiJ9.e30~".to_owned(),
        ),
        (
            "a disclosure of four elements",
            "disclosure_malformed",
            ParseError::Disclosure {
                disclosure: first,
                fault: DisclosureFault::Length(4),
            },
            compact("{}", &[&four]),
        ),
        (
            "a truncated digest",
            "sd_alg_unsupported",
            ParseError::UnsupportedSdAlg(SdAlgFault::Unknown("sha-256-32".to_owned())),
            compact(r#"{"_sd_alg":"sha-256-32"}"#, &[]),
        ),
        (
            "a disclosure named _sd",
            "reserved_claim_name",
            reserved_name(ReservedFault::Disclosed("_sd".to_owned())),
            compact(&json!({"_sd": [reserved_digest]}).to_string(), &[&reserved]),
        ),
        (
            "an object member named ...",
            "reserved_claim_name",
            reserved_name(ReservedFault::Ellipsis),
            compact(&json!({"a": {"...": x}}).to_string(), &[]),
        ),
        (
            "a nested _sd_alg",
            "reserved_claim_name",
            reserved_name(ReservedFault::NestedSdAlg),
            compact(r#"{"a":{"_sd_alg":"sha-256"}}"#, &[]),
        ),
        (
            "an _sd holding a number",
            "reserved_claim_name",
            reserved_name(ReservedFault::SdDigest),
            compact(r#"{"_sd":[1]}"#, &[]),
        ),
        (
            "an array digest beside another member",
            "reserved_claim_name",
            reserved_name(ReservedFault::ElementMembers),
            compact(&json!({"a": [{"...": x, "b": 1}]}).to_string(), &[]),
        ),
        (
            "a decoy twice",
            "digest_repeated",
            ParseError::RepeatedDigest(Digest::new(&x)),
            compact(&json!({"_sd": [x, x]}).to_string(), &[]),
        ),
        (
            "a disclosure twice",
            "digest_repeated",
            ParseError::RepeatedDigest(Digest::new(&property_digest)),
            compact(
                &json!({"_sd": [property_digest]}).to_string(),
                &[&property, &property],
            ),
        ),
        (
            "an element disclosure in _sd",
            "disclosure_misplaced",
            ParseError::MisplacedDisclosure {
                disclosure: first,
                placement: Placement::ElementInObject,
            },
            compact(&json!({"_sd": [element_digest]}).to_string(), &[&element]),
        ),
        (
            "a property disclosure in an array",
            "disclosure_misplaced",
            ParseError::MisplacedDisclosure {
                disclosure: first,
                placement: Placement::PropertyInArray,
            },
            compact(
                &json!({"a": [{"...": property_digest}]}).to_string(),
                &[&property],
            ),
        ),
        (
            "a disclosure of a permanent claim's name",
            "claim_name_exists",
            ParseError::ClaimNameExists("given_name".to_owned()),
            compact(
                &json!({"given_name": "a", "_sd": [taken_digest]}).to_string(),
                &[&taken],
            ),
        ),
        (
            "a disclosure no digest names",
            "disclosure_unreferenced",
            ParseError::UnreferencedDisclosure(first),
            compact("{}", &[&property]),
        ),
        (
            "41 levels of arrays",
            "claims_too_deep",
            ParseError::TooDeep,
            compact(&deep, &[]),
        ),
    ];
    // An empty disclosure ends before its value: serde_json's position is its own.
    match SdJwt::parse(&compact("{}", &[""])) {
        Err(ParseError::Disclosure {
            disclosure,
            fault:
                DisclosureFault::Encoding(EncodedJsonFault::Json(JsonFault::Read(ReadFault::Text(
                    text,
                )))),
        }) => {
            assert_eq!(disclosure, first);
            assert_eq!(text.kind(), JsonTextFault::Eof);
        }
        other => panic!("an empty disclosure: {:?}", other.err()),
    }
    for (case, code, cause, sd_jwt) in rows {
        match SdJwt::parse(&sd_jwt) {
            Ok(_) => panic!("{case}: accepted"),
            Err(e) => {
                assert_eq!(e.code(), code, "{case}");
                assert_eq!(e, cause, "{case}");
            }
        }
    }
}
