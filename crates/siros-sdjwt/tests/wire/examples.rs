//! The examples of RFC 9901, Section 5 and Appendices A.1 to A.4.
//!
//! SOURCE: RFC 9901 (November 2025), https://www.rfc-editor.org/rfc/rfc9901.txt. The files
//! under `rfc9901/` are its blocks verbatim, without the three-space indent:
//!
//! - `input.json`: the input JWT Claims Set;
//! - `issued.txt`: the issued SD-JWT (Sections 5.1, A.3, A.4);
//! - `disclosures.txt`: every Disclosure the example lists (A.1, A.2);
//! - `presentation.txt`: the presentation, with its KB-JWT where the example binds a key;
//! - `processed.json`: the Processed SD-JWT Payload the verifier gets from the presentation.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_openid4vp::claims::kit::ClaimsFormat;
use siros_openid4vp::claims::{ClaimPath, ConcretePath};
use siros_openid4vp::json::Node;
use siros_sdjwt::{Audience, Binding, KbNonce, NumericDate, SdJwt, SdJwtVc};
use siros_testkit::sd_jwt_reading::{SdJwtReadError, read};

use crate::common::{compact_fixture, issued, json_fixture, processed};

/// Each example and the pointers to the claims its presentation discloses, in its order.
const EXAMPLES: [(&str, &str); 5] = [
    (
        "s5",
        r#"[["family_name"], ["address"], ["given_name"], ["nationalities", 0]]"#,
    ),
    ("a1", r#"[["address", "region"], ["address", "country"]]"#),
    (
        "a2",
        r#"[["verified_claims", "verification", "time"],
            ["verified_claims", "verification", "evidence", 0, "method"],
            ["verified_claims", "claims", "given_name"],
            ["verified_claims", "claims", "family_name"],
            ["verified_claims", "claims", "address"]]"#,
    ),
    // The parent `age_equal_or_over` comes with its member `18`.
    ("a3", r#"[["age_equal_or_over", "18"], ["nationalities"]]"#),
    (
        "a4",
        r#"[["credentialSubject", "order"],
            ["credentialSubject", "dateOfVaccination"],
            ["credentialSubject", "vaccine", "atcCode"],
            ["credentialSubject", "vaccine", "medicinalProductName"]]"#,
    ),
];

/// The issued SD-JWT holds every input claim; the core's pointer walk over its values selects the
/// RFC's presentation byte for byte; the Verifier's processed payload and the Key Binding JWT's
/// header and payload, `sd_hash` included, equal the RFC's; a disclosure removed from the RFC's
/// presentation fails `sd_hash`.
#[test]
fn rfc9901_examples() {
    let format = SdJwtVc::new().unwrap();
    for (dir, pointers) in EXAMPLES {
        let sd_jwt = SdJwt::parse(&issued(dir)).unwrap_or_else(|e| panic!("{dir}: {e}"));
        let full = processed(sd_jwt.claims());
        let input = json_fixture(&format!("{dir}/input.json"));
        for member in input.as_object().unwrap().members() {
            assert_eq!(
                full.get(&member.name),
                Some(&member.value),
                "{dir}: {}",
                member.name
            );
        }

        let stated = compact_fixture(&format!("{dir}/presentation.txt"));
        let (sent, kb_jwt) = stated.split_at(stated.rfind('~').unwrap() + 1);
        let values = sd_jwt.values().unwrap();
        let pointers = Node::parse(pointers).unwrap();
        let paths: Vec<ConcretePath<'_>> = pointers
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|pointer| {
                ClaimPath::parse(pointer)
                    .unwrap()
                    .select_held(&values, |element| format.withheld(element))
                    .unwrap()
                    .into_iter()
                    .map(|(path, _)| path)
            })
            .collect();
        let presentation = sd_jwt.select(&paths).unwrap();
        assert_eq!(presentation.as_str(), sent, "{dir}");

        let shown = SdJwt::parse(sent).unwrap_or_else(|e| panic!("{dir}: {e}"));
        let expected = json_fixture(&format!("{dir}/processed.json"));
        assert_eq!(processed(shown.claims()), expected, "{dir}");

        if kb_jwt.is_empty() {
            continue;
        }
        assert!(read(&stated).is_ok(), "{dir}");
        let (first, rest) = sent.split_once('~').unwrap();
        let (_, others) = rest.split_once('~').unwrap();
        assert_eq!(
            read(&format!("{first}~{others}{kb_jwt}")).map(|_| ()),
            Err(SdJwtReadError::SdHash),
            "{dir}"
        );
        let mut segments = kb_jwt.split('.');
        let header = decoded(segments.next().unwrap());
        let payload = decoded(segments.next().unwrap());
        let binding = presentation
            .key_binding(
                Binding {
                    alg: header.get("alg").unwrap().as_str().unwrap(),
                    iat: NumericDate(match payload.get("iat") {
                        Some(Node::Number(iat)) => iat.as_u64().unwrap(),
                        other => panic!("{other:?}"),
                    }),
                    aud: &Audience::new(payload.get("aud").unwrap().as_str().unwrap()),
                    nonce: &KbNonce::new(payload.get("nonce").unwrap().as_str().unwrap()),
                },
                [],
            )
            .unwrap();
        let input = std::str::from_utf8(binding.signing_input()).unwrap();
        let (our_header, our_payload) = input.split_once('.').unwrap();
        assert_eq!(decoded(our_header), header, "{dir}");
        assert_eq!(decoded(our_payload), payload, "{dir}");
    }
}

fn decoded(segment: &str) -> Node<'static> {
    let bytes = URL_SAFE_NO_PAD.decode(segment).unwrap();
    Node::parse(std::str::from_utf8(&bytes).unwrap())
        .unwrap()
        .into_owned()
}
