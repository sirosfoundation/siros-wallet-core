//! D1 over the private data specification's vectors (3.1 §5A): both claims formats' registration
//! keeps `auxiliary_data` out of a view, whichever way the Credential Response carries it.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use siros_mdoc::registration as mdoc;
use siros_openid4vp::claims::kit::IssuedMetadata;
use siros_openid4vp::json::Node;
use siros_testkit::{issuer, sd_jwt_issuer};

const VECTORS: &str = include_str!("../../../siros-wallet-state/tests/privatedata/vectors.jsonl");

fn vector(id: &str) -> Value {
    VECTORS
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("vector"))
        .find(|vector| vector["id"] == id)
        .expect("the vector")
}

fn node(value: &Value) -> Node<'static> {
    Node::parse(&value.to_string()).expect("json").into_owned()
}

/// The view of each format's registration over the configuration's and the response's metadata.
fn views(configuration: Option<&Value>, response: &Value) -> [Node<'static>; 2] {
    let issued = || IssuedMetadata {
        configuration: configuration.map(node),
        response: Some(node(response)),
        ..IssuedMetadata::default()
    };
    let credential = |extra: &str| {
        Node::parse(&format!(
            r#"{{"type": "t", "metadata": {{}}, "values": {{"ns": {{"a": 1}}}}, {extra}}}"#
        ))
        .expect("view")
        .into_owned()
    };
    let compact = sd_jwt_issuer::issue(&credential(r#""alg": "ES256", "curve": "P-256""#))
        .expect("the SD-JWT");
    let sd_jwt = siros_sdjwt::Registered::of(
        &compact,
        &siros_sdjwt::Resolved {
            issued: issued(),
            ..siros_sdjwt::Resolved::default()
        },
    )
    .expect("registered");
    let stored = issuer::issue(&credential(
        r#""issuer_alg": -7, "device_alg": -7, "device_curve": "P-256""#,
    ))
    .expect("the mdoc");
    let mdoc = mdoc::Registered::of(
        &URL_SAFE_NO_PAD.encode(stored),
        &mdoc::Resolved {
            issued: issued(),
            ..mdoc::Resolved::default()
        },
    )
    .expect("registered");
    [sd_jwt.view().to_vec(), mdoc.view().to_vec()].map(|view| {
        Node::parse(std::str::from_utf8(&view).expect("UTF-8"))
            .expect("view")
            .into_owned()
    })
}

/// `delivered-secret-strip-001`'s merge and strip, over each format.
#[test]
fn the_strip_vector_holds_over_both_formats() {
    let vector = vector("delivered-secret-strip-001");
    let cases = vector["inputs"]["cases"].as_array().expect("cases");
    for case in cases {
        let response = &case["responseCredentialMetadata"];
        let opening = response["auxiliary_data"][0]["opening"]
            .as_str()
            .expect("opening");
        let merged = node(&case["expected"]["mergedDisplayMetadata"]);
        let stripped = node(&case["expected"]["strippedResponse"]);
        for view in views(Some(&case["issuerCredentialMetadata"]), response) {
            let written = view.python_compact().to_string();
            assert_eq!(written.matches("auxiliary_data").count(), 0, "{case}");
            assert_eq!(written.matches(opening).count(), 0, "{case}");
            assert_eq!(view.get("metadata"), Some(&merged), "{case}");
        }
        for view in views(None, response) {
            assert_eq!(view.get("metadata"), Some(&stripped), "{case}");
        }
    }
}

/// `delivered-secret-wire-001`: the Credential Response's `credential_metadata` in each of the
/// vector's shapes reaches no view.
#[test]
fn the_wire_vector_reaches_no_view() {
    let vector = vector("delivered-secret-wire-001");
    let cases = vector["inputs"]["cases"].as_array().expect("cases");
    for case in cases {
        let response = &case["response"]["credential_metadata"];
        for view in views(None, response) {
            let written = view.python_compact().to_string();
            assert_eq!(written.matches("auxiliary_data").count(), 0, "{case}");
            assert_eq!(written.matches("opening").count(), 0, "{case}");
        }
    }
}
