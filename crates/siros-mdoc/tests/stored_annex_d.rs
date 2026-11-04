//! The example of ISO/IEC 18013-5, Annex D, D.4.1.2, read as a stored credential.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_mdoc::stored::StoredMdoc;
use siros_openid4vp::cbor::Value;

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
}
