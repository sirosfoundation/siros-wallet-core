//! The example of ISO/IEC 18013-5, Annex D, D.4.1.2, read as a stored credential, and the
//! responses built from it.

use siros_codec::base64url;
use siros_codec::cbor::Value;
use siros_codec::signature::Es256Signature;
use siros_mdoc::{ElementId, Mdoc};

const DEVICE_RESPONSE: &str = include_str!("vectors/annex_d_device_response.hex");
const NAME_SPACE: &str = "org.iso.18013.5.1";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn annex_d() -> Mdoc {
    Mdoc::parse(&base64url::encode(&unhex(DEVICE_RESPONSE.trim())).into_string()).unwrap()
}

/// The standard's statements about its example: the mDL `docType`, six items of
/// `org.iso.18013.5.1`, and `family_name` "Doe".
#[test]
fn annex_d_known_answers() {
    let mdoc = annex_d();
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
    assert_eq!(family_name.value(), &Value::text("Doe"));
}

/// Every pair of the example's items, disclosed and read back from the `DeviceResponse`, gives
/// exactly that pair in the issuer's bytes, and `issuerAuth` as issued.
#[test]
fn disclosed_pairs_read_back_as_issued() {
    let mdoc = annex_d();
    let items = mdoc.name_spaces()[0].items();
    for (i, first) in items.iter().enumerate() {
        for second in &items[i + 1..] {
            let selection = [second, first].map(|item| ElementId {
                name_space: NAME_SPACE,
                identifier: item.identifier().as_str(),
            });
            let disclosure = mdoc.disclose(&selection, Vec::new()).unwrap();
            let response = disclosure.device_response(&Es256Signature::new([0x5a; 64]));
            let read = Mdoc::parse(&base64url::encode(&response).into_string()).unwrap();
            let disclosed: Vec<(&str, &[u8])> = read
                .name_spaces()
                .iter()
                .flat_map(|n| {
                    n.items()
                        .iter()
                        .map(|item| (n.name().as_str(), item.bytes()))
                })
                .collect();
            assert_eq!(
                disclosed,
                [(NAME_SPACE, first.bytes()), (NAME_SPACE, second.bytes())]
            );
            assert_eq!(read.doc_type(), mdoc.doc_type());
            assert_eq!(read.issuer_auth().as_cbor(), mdoc.issuer_auth().as_cbor());
        }
    }
}
