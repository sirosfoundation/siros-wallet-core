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

use serde_json::Value;
use siros_codec::base64url;
use siros_codec::date::DateTime;
use siros_dcql::ClaimPath;
use siros_sdjwt::{Audience, KbNonce, NumericDate, SdJwt};

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

/// The issued SD-JWT holds every input claim; selection rebuilds the RFC's presentation byte for
/// byte; the verifier's processed payload and the KB-JWT header and payload, `sd_hash`
/// included, equal the RFC's.
#[test]
fn rfc9901_examples() {
    for (dir, pointers) in EXAMPLES {
        let sd_jwt = SdJwt::parse(&issued(dir)).unwrap_or_else(|e| panic!("{dir}: {e}"));
        let full = processed(sd_jwt.claims());
        for (name, value) in json_fixture(&format!("{dir}/input.json"))
            .as_object()
            .unwrap()
        {
            assert_eq!(full.get(name), Some(value), "{dir}: {name}");
        }

        let stated = compact_fixture(&format!("{dir}/presentation.txt"));
        let (sent, kb_jwt) = stated.split_at(stated.rfind('~').unwrap() + 1);
        let pointers: Vec<ClaimPath> = serde_json::from_str(pointers).unwrap();
        let presentation = sd_jwt.select(&pointers).unwrap();
        assert_eq!(presentation.as_str(), sent, "{dir}");

        let shown = SdJwt::parse(sent).unwrap_or_else(|e| panic!("{dir}: {e}"));
        let expected = json_fixture(&format!("{dir}/processed.json"));
        assert_eq!(processed(shown.claims()), expected, "{dir}");

        if kb_jwt.is_empty() {
            continue;
        }
        let mut segments = kb_jwt.split('.');
        let header = decoded(segments.next().unwrap());
        let payload = decoded(segments.next().unwrap());
        let binding = presentation
            .key_binding(
                NumericDate::of(DateTime::from_unix(payload["iat"].as_i64().unwrap()).unwrap())
                    .unwrap(),
                &Audience::new(payload["aud"].as_str().unwrap()),
                &KbNonce::new(payload["nonce"].as_str().unwrap()),
                &[],
            )
            .unwrap();
        let input = std::str::from_utf8(binding.signing_input()).unwrap();
        let (our_header, our_payload) = input.split_once('.').unwrap();
        assert_eq!(decoded(our_header), header, "{dir}");
        assert_eq!(decoded(our_payload), payload, "{dir}");
    }
}

fn decoded(segment: &str) -> Value {
    serde_json::from_slice(&base64url::decode(segment).unwrap()).unwrap()
}
