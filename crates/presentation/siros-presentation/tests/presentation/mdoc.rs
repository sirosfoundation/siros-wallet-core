//! The honest path of an mdoc over the DC API with `dc_api.jwt`: the DeviceResponse carries the
//! selected elements, and its device signature verifies over the DeviceAuthentication of the
//! SessionTranscript the verifier computes from its own values (A7).

use ciborium::Value as Ciborium;
use serde_json::json;
use siros_codec::base64url;
use siros_codec::cbor::Value as Cbor;

use crate::verifier::{
    client_metadata, dc_api_transcript, dc_api_unsigned, decrypt_jwe, NONCE, ORIGIN,
};
use crate::wallet::{ciborium, holder_signed, mdoc, respond, Held, Wallet, MDL, MDL_NS};

fn text(s: &str) -> Ciborium {
    Ciborium::Text(s.into())
}

fn get<'v>(map: &'v Ciborium, key: &str) -> &'v Ciborium {
    crate::verifier::get(map, &text(key))
}

fn encode(value: &Ciborium) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

/// The element identifiers of `items`, a namespace's `IssuerSignedItemBytes`.
fn identifiers(items: &Ciborium) -> Vec<String> {
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            let Ciborium::Tag(24, bytes) = item else {
                panic!("IssuerSignedItemBytes")
            };
            let item = ciborium(bytes.as_bytes().unwrap());
            get(&item, "elementIdentifier")
                .as_text()
                .unwrap()
                .to_owned()
        })
        .collect()
}

#[test]
fn mdoc_over_dc_api_jwt() {
    let wallet = Wallet::new(vec![Held::new(
        1,
        "mso_mdoc",
        mdoc(
            MDL,
            MDL_NS,
            &[
                ("family_name", Cbor::text("Doe")),
                ("given_name", Cbor::text("Jane")),
                ("age_over_18", Cbor::Bool(true)),
            ],
        ),
    )]);
    let request = dc_api_unsigned(&json!({
        "response_type": "vp_token",
        "response_mode": "dc_api.jwt",
        "nonce": NONCE,
        "client_metadata": client_metadata(),
        "dcql_query": {"credentials": [{"id": "mdl", "format": "mso_mdoc",
            "meta": {"doctype_value": MDL},
            "claims": [{"path": [MDL_NS, "family_name"]}, {"path": [MDL_NS, "age_over_18"]}]}]}
    }));
    let response = respond(&wallet.input(&request));

    let payload = decrypt_jwe(response.submission());
    assert!(payload.get("state").is_none());
    let encoded = payload["vp_token"]["mdl"][0].as_str().unwrap();
    let device_response = ciborium(&base64url::decode(encoded).unwrap());
    let documents = get(&device_response, "documents").as_array().unwrap();
    let [document] = &documents[..] else {
        panic!("one document")
    };
    assert_eq!(get(document, "docType"), &text(MDL));
    let name_spaces = get(get(document, "issuerSigned"), "nameSpaces");
    assert_eq!(
        identifiers(get(name_spaces, MDL_NS)),
        ["family_name", "age_over_18"]
    );

    let device_signed = get(document, "deviceSigned");
    let device_name_spaces = get(device_signed, "nameSpaces");
    let empty = Ciborium::Tag(
        24,
        Box::new(Ciborium::Bytes(encode(&Ciborium::Map(vec![])))),
    );
    assert_eq!(device_name_spaces, &empty);
    let signature = get(get(device_signed, "deviceAuth"), "deviceSignature");
    let [Ciborium::Bytes(protected), _, Ciborium::Null, Ciborium::Bytes(signature)] =
        &signature.as_array().unwrap()[..]
    else {
        panic!("a COSE_Sign1 with a detached payload")
    };
    // ISO/IEC 18013-5, 9.1.3.4 and 9.1.3.6.
    let authentication = Ciborium::Array(vec![
        text("DeviceAuthentication"),
        ciborium(&dc_api_transcript()),
        text(MDL),
        empty,
    ]);
    let authentication = Ciborium::Tag(24, Box::new(Ciborium::Bytes(encode(&authentication))));
    let sig_structure = Ciborium::Array(vec![
        text("Signature1"),
        Ciborium::Bytes(protected.clone()),
        Ciborium::Bytes(Vec::new()),
        Ciborium::Bytes(encode(&authentication)),
    ]);
    assert!(holder_signed(&encode(&sig_structure), signature));

    let record = serde_json::to_value(response.record()).unwrap();
    assert_eq!(record["usedCredentialIds"], json!([1]));
    assert_eq!(record["audience"], format!("origin:{ORIGIN}"));
}
