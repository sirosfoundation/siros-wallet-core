//! D1 over the private data specification's vectors (3.1 §5A): both claims formats' registration
//! keeps `auxiliary_data` out of a view, wherever an input carries it.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
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
    registered(None, &|| IssuedMetadata {
        configuration: configuration.map(node),
        response: Some(node(response)),
        ..IssuedMetadata::default()
    })
}

/// The view of each format's registration; an mdoc's format states no document of its own.
fn registered(
    type_metadata: Option<&Value>,
    issued: &dyn Fn() -> IssuedMetadata<'static>,
) -> [Node<'static>; 2] {
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
            metadata: type_metadata.map(node),
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
            let written = view.json_compact().to_string();
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
            let written = view.json_compact().to_string();
            assert_eq!(written.matches("auxiliary_data").count(), 0, "{case}");
            assert_eq!(written.matches("opening").count(), 0, "{case}");
            for stored in case["expected"]["storedMetadataPerCredential"]
                .as_array()
                .expect("stored")
                .iter()
                .filter(|stored| stored["type"] != "auxiliary_data")
            {
                let metadata = view.get("metadata").expect("metadata");
                let member = metadata.get(stored["type"].as_str().expect("type"));
                assert_eq!(member, Some(&node(&stored["value"])), "{case}");
            }
        }
    }
}

/// `auxiliary_data` written under a display entry, a claim or another member reaches no view.
#[test]
fn a_delivered_secret_reaches_no_view_at_any_depth() {
    let secret = json!([{"opening": "SECRET"}]);
    let entry = json!({"name": "n", "locale": "en", "auxiliary_data": secret});
    let display = json!({"display": [entry]});
    let claims = json!({"claims": [{"path": ["a"], "auxiliary_data": secret, "display": [entry]}]});
    let member = json!({"com.example.x": {"auxiliary_data": secret}});
    let issued = |issuer_display: Option<&Value>, configuration, response| IssuedMetadata {
        issuer_display: issuer_display.map(node),
        configuration,
        response,
    };
    let cases: [(Option<&Value>, IssuedMetadata<'static>); 8] = [
        (Some(&display), IssuedMetadata::default()),
        (Some(&claims), IssuedMetadata::default()),
        (Some(&member), IssuedMetadata::default()),
        (None, issued(Some(&json!([entry])), None, None)),
        (None, issued(None, Some(node(&display)), None)),
        (None, issued(None, Some(node(&member)), None)),
        (None, issued(None, None, Some(node(&claims)))),
        (
            Some(&display),
            issued(None, Some(node(&claims)), Some(node(&member))),
        ),
    ];
    for (type_metadata, input) in &cases {
        for view in registered(*type_metadata, &|| input.clone()) {
            let written = view.json_compact().to_string();
            assert_eq!(written.matches("auxiliary_data").count(), 0, "{input:?}");
            assert_eq!(written.matches("SECRET").count(), 0, "{input:?}");
        }
    }
}
