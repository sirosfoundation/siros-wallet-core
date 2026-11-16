//! The claims path pointer examples of OpenID4VP 1.0, Section 7.3, through `Credential`.
//!
//! SOURCE: OpenID for Verifiable Presentations 1.0,
//! https://openid.net/specs/openid-4-verifiable-presentations-1_0.html, Section 7.3, "Claims
//! Path Pointer Example": the example credential and the pointers with the selections the
//! section states. The credential is issued here as an SD-JWT VC with a `vct`; `address`, two
//! of its members, the `degrees` elements and the second nationality are selectively
//! disclosed, and `degrees` holds a decoy at its end.

use serde_json::{json, Value};
use siros_dcql::{ClaimPath, Credential as _};

use crate::common::{credential, disclosure, json, sd_jwt};

const EXAMPLE: &str = r#"{
  "name": "Arthur Dent",
  "address": {
    "street_address": "42 Market Street",
    "locality": "Milliways",
    "postal_code": "12345"
  },
  "degrees": [
    {
      "type": "Bachelor of Science",
      "university": "University of Betelgeuse"
    },
    {
      "type": "Master of Science",
      "university": "University of Betelgeuse"
    }
  ],
  "nationalities": ["British", "Betelgeusian"]
}"#;

#[test]
fn section_7_3_examples() {
    let example: Value = serde_json::from_str(EXAMPLE).unwrap();
    let address = &example["address"];
    let (locality, locality_digest) = disclosure(&json!(["s0", "locality", address["locality"]]));
    let (postal_code, postal_code_digest) =
        disclosure(&json!(["s1", "postal_code", address["postal_code"]]));
    let (address_disclosure, address_digest) = disclosure(&json!([
        "s2",
        "address",
        {
            "street_address": address["street_address"],
            "_sd": [locality_digest, postal_code_digest]
        }
    ]));
    let (bachelor, bachelor_digest) = disclosure(&json!(["s3", example["degrees"][0]]));
    let (master, master_digest) = disclosure(&json!(["s4", example["degrees"][1]]));
    let (betelgeusian, betelgeusian_digest) =
        disclosure(&json!(["s5", example["nationalities"][1]]));
    let decoy = disclosure(&json!(["s6", "never issued"])).1;
    let payload = json!({
        "vct": "https://credentials.example/hitchhiker",
        "name": example["name"],
        "_sd": [address_digest],
        "degrees": [
            {"...": bachelor_digest},
            {"...": master_digest},
            {"...": decoy}
        ],
        "nationalities": [example["nationalities"][0], {"...": betelgeusian_digest}]
    });
    let data = sd_jwt(
        &payload,
        &[
            &locality,
            &postal_code,
            &address_disclosure,
            &bachelor,
            &master,
            &betelgeusian,
        ],
    );
    let credential = credential("dc+sd-jwt", &data);

    let rows: [(&str, Value); 5] = [
        // "The claim name with the value Arthur Dent is selected."
        (r#"["name"]"#, json!(["Arthur Dent"])),
        // "The claim address with its sub-claims as the value is selected."
        (r#"["address"]"#, json!([example["address"]])),
        // "The claim street_address with the value 42 Market Street is selected."
        (
            r#"["address", "street_address"]"#,
            json!(["42 Market Street"]),
        ),
        // "All type claims in the degrees array are selected."
        (
            r#"["degrees", null, "type"]"#,
            json!(["Bachelor of Science", "Master of Science"]),
        ),
        // "The second nationality is selected."
        (r#"["nationalities", 1]"#, json!(["Betelgeusian"])),
    ];
    for (pointer, selected) in rows {
        let path: ClaimPath = serde_json::from_str(pointer).unwrap();
        let typed: Vec<Value> = credential
            .claims(&path)
            .unwrap()
            .into_iter()
            .map(json)
            .collect();
        assert_eq!(Value::Array(typed), selected, "{pointer}");
        let compared = credential.claim(&path).unwrap();
        assert_eq!(Value::Array(compared), selected, "{pointer}");
    }
}
