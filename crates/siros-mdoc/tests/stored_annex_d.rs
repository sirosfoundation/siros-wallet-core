//! The example of ISO/IEC 18013-5, Annex D, D.4.1.2, read as a stored credential.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_mdoc::registration::{Registered, Resolved};
use siros_mdoc::stored::StoredMdoc;
use siros_openid4vp::cbor::Value;
use siros_openid4vp::host::Timestamp;
use siros_openid4vp::json::Node;

const DEVICE_RESPONSE: &str = include_str!("vectors/annex_d_device_response.hex");
const NAME_SPACE: &str = "org.iso.18013.5.1";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// The standard's statements about its example: the mDL `docType`, six items of
/// `org.iso.18013.5.1`, each matching its digest in the MSO, and `family_name` "Doe".
#[test]
fn annex_d_known_answers() {
    let data = URL_SAFE_NO_PAD.encode(unhex(DEVICE_RESPONSE.trim()));
    let mdoc = StoredMdoc::parse(&data).unwrap();
    assert_eq!(mdoc.doc_type(), "org.iso.18013.5.1.mDL");
    let [name_space] = mdoc.name_spaces() else {
        panic!("one namespace");
    };
    assert_eq!(name_space.name(), NAME_SPACE);
    assert_eq!(name_space.items().len(), 6);
    let family_name = name_space
        .items()
        .iter()
        .find(|item| item.identifier() == "family_name")
        .unwrap();
    assert_eq!(family_name.value(), &Value::Text("Doe".to_owned()));
    // D.4.1.2's validityInfo: 2020-10-01T13:30:02Z, valid until 2021-10-01T13:30:02Z.
    let validity = mdoc.mso().validity();
    assert_eq!(validity.valid_from(), Timestamp(1_601_559_002));
    assert_eq!(validity.valid_until(), Timestamp(1_633_095_002));

    // The registration's view: the Annex's type, values, signer, key and validity.
    let registered = Registered::of(&data, &Resolved::default()).unwrap();
    assert_eq!(registered.document(), mdoc.issuer_signed());
    let view = Node::parse(std::str::from_utf8(registered.view()).unwrap()).unwrap();
    let text = |name: &str| view.get(name).and_then(Node::as_str);
    let number = |name: &str| view.get(name).map(|n| n.json_compact().to_string());
    assert_eq!(text("type"), Some("org.iso.18013.5.1.mDL"));
    let values = view.get("values").unwrap().get(NAME_SPACE).unwrap();
    assert_eq!(
        values.get("family_name").and_then(Node::as_str),
        Some("Doe")
    );
    assert_eq!(number("issuer_alg").as_deref(), Some("-7"));
    assert_eq!(number("device_alg").as_deref(), Some("-7"));
    assert_eq!(text("device_curve"), Some("P-256"));
    let validity = view.get("validity").unwrap();
    assert_eq!(
        validity
            .get("not_before")
            .map(|n| n.json_compact().to_string())
            .as_deref(),
        Some("1601559002")
    );
    assert_eq!(
        validity
            .get("not_after")
            .map(|n| n.json_compact().to_string())
            .as_deref(),
        Some("1633095002")
    );
}
