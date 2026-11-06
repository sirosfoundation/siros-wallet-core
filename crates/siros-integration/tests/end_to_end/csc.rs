//! CSC §7.3 through each format.

use crate::common::HaipHost;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use siros_openid4vp::effects::MediaType;
use siros_openid4vp::host::Timestamp;
use siros_openid4vp::rows::HttpsUrl;
use siros_testkit::fixtures::{self, Held, parameters};
use siros_testkit::verifier;
use siros_testkit::{Published, PublishedResource};

use crate::common::sri;

use super::{NOW, answer, csc, hex, presentation, read_mdoc, read_sd_jwt};

/// CSC §7.3's request and entry: the entry's credential_ids name the example request's query,
/// whose id it misnames, and its document's checksum is the integrity of the document published
/// at its href (CSC §6.3: phase 2 fetches it and verifies it).
fn csc_7_3(format_query: &str) -> (String, String, Published) {
    let published = b"%PDF-1.7 Example Terms of Service";
    let mut entry: Value = serde_json::from_str(&csc("csc-7.3-entry")).expect("§7.3's entry");
    entry["credential_ids"] = json!(["qscd_service_attestation"]);
    entry["documentInfos"][0]["checksum"] = json!(sri(published));
    let href = entry["documentInfos"][0]["href"]
        .as_str()
        .expect("href")
        .to_owned();
    let entry = verifier::encode(&entry.to_string()).expect("an entry");
    let text = parameters(
        &format!(r#"{{"credentials": [{format_query}]}}"#),
        &format!(r#""transaction_data":["{entry}"]"#),
    );
    let published = Published::new(vec![PublishedResource {
        url: HttpsUrl::parse(&href).expect("an https URL"),
        content: published.to_vec(),
        media: MediaType::parse("application/pdf").expect("a media type"),
    }]);
    (entry, text, published)
}

#[test]
fn csc_7_3_through_an_mdoc_answers_with_its_device_signed_qes_approval() {
    let request_json: Value =
        serde_json::from_str(&csc("csc-7.3-request")).expect("§7.3's request");
    let query = request_json["dcql_query"]["credentials"][0].to_string();
    let (entry, text, published) = csc_7_3(&query);
    let received = fixtures::unsigned(&text).expect("received");
    let request = fixtures::request_of(&received).expect("request");
    // §7.3's service user attestation; §7.2.1.1 Note 21: the MSO authorizes qesApproval, and
    // the rulebook lets it approve the qualified signature (§7.2.1 Note 22).
    let mut attestation = Held::new(
        "attestation",
        "mso_mdoc",
        r#"{"type": "com.example.service.1.attestation", "metadata": {},
            "values": {"com.example.service.1": {"userName": "willeke", "credentialID": "GX0112348"}},
            "key_authorizations": {"namespaces": [], "elements": {"org.cloudsignatureconsortium.dm.1": ["qesApproval"]}},
            "issuer_alg": -7, "issuer_curve": "P-256", "device_alg": -7, "device_curve": "P-256"}"#,
    )
    .with_issued()
    .expect("the attestation's IssuerSigned");
    attestation.documents.push((
        "qes".to_owned(),
        r#"{"signature_qualifiers": ["eu_eidas_qes"]}"#.as_bytes().to_vec(),
    ));
    let answered = answer(
        &request,
        &[attestation],
        &published,
        &HaipHost::at(Timestamp(NOW)),
    );
    let response = read_mdoc(&presentation(&answered, "qscd_service_attestation"));
    // §7.3's DeviceResponse: the attributes issuer-signed, qesApproval device-signed, the
    // SHA-256 digest of the decoded entry as a 32-byte bstr (§7.2.1.1, Note 20).
    let decoded = URL_SAFE_NO_PAD.decode(&entry).expect("base64url");
    let digest = Sha256::digest(&decoded);
    assert_eq!(digest.len(), 32);
    assert_eq!(
        (&response["version"], &response["status"]),
        (&json!("1.0"), &json!(0))
    );
    let [document] = response["documents"]
        .as_array()
        .expect("documents")
        .as_slice()
    else {
        panic!("one document");
    };
    assert_eq!(
        document["docType"],
        json!("com.example.service.1.attestation")
    );
    assert_eq!(
        document["issuerSigned"]["nameSpaces"],
        json!({"com.example.service.1": {"userName": "willeke", "credentialID": "GX0112348"}})
    );
    assert_eq!(
        document["deviceSigned"]["nameSpaces"],
        json!({"org.cloudsignatureconsortium.dm.1": {"qesApproval": {"bstr": hex(&digest)}}})
    );
}

#[test]
fn csc_7_3_through_an_sd_jwt_answers_with_its_key_binding_jwt_qes_approval() {
    // §7.3's attestation as an SD-JWT VC (§7.2.1.2): its attributes are top-level claims; the
    // approval is a Key Binding JWT claim, which no query claim names.
    let query = r#"{"id": "qscd_service_attestation", "format": "dc+sd-jwt", "meta": {"vct_values": ["com.example.service.1.attestation"]},
        "claims": [{"path": ["userName"], "values": ["willeke"]}, {"path": ["credentialID"], "values": ["GX0112348"]}]}"#;
    let (entry, text, published) = csc_7_3(query);
    let received = fixtures::unsigned(&text).expect("received");
    let request = fixtures::request_of(&received).expect("request");
    let mut attestation = Held::new(
        "attestation",
        "dc+sd-jwt",
        r#"{"type": "com.example.service.1.attestation", "metadata": {}, "values": {"userName": "willeke", "credentialID": "GX0112348"},
            "alg": "ES256", "curve": "P-256", "key_alg": "ES256", "key_curve": "P-256"}"#,
    );
    attestation = attestation.with_issued().expect("the issued SD-JWT");
    attestation.documents.push((
        "qes".to_owned(),
        r#"{"signature_qualifiers": ["eu_eidas_qes"]}"#.as_bytes().to_vec(),
    ));
    let answered = answer(
        &request,
        &[attestation],
        &published,
        &HaipHost::at(Timestamp(NOW)),
    );
    let presentation = read_sd_jwt(&presentation(&answered, "qscd_service_attestation"));
    let payload = presentation["kb_jwt"]["payload"]
        .as_object()
        .expect("a Key Binding JWT");
    // §7.2.1.2: the top-level claim org.cloudsignatureconsortium.dm.1.qesApproval, a String:
    // the base64 SHA-256 digest (§7.2) of the base64url entry as received; beside it the Key
    // Binding JWT's own claims (B.3.6).
    let mut names: Vec<&str> = payload.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "aud",
            "iat",
            "nonce",
            "org.cloudsignatureconsortium.dm.1.qesApproval",
            "sd_hash"
        ]
    );
    assert_eq!(
        payload["org.cloudsignatureconsortium.dm.1.qesApproval"],
        json!(STANDARD.encode(Sha256::digest(entry.as_bytes())))
    );
}
