//! The mdoc presentation (OpenID4VP 1.0 B.2.5, ISO/IEC 18013-5 §8.3.2.1.2.2, §9.1.3), read as a
//! Verifier reads it: how the device authenticates, as the reference model's check_respond.py
//! states it; OpenID4VP B.2.6's handover examples through the SessionTranscript; the document
//! over seeded random credentials, options and members; and what the plug-in refuses to present.

use std::borrow::Cow;
use std::error::Error as _;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};
use siros_mdoc::issuer_signed::IssuedError;
use siros_mdoc::{Handover, Mdoc, SessionTranscript, Thumbprint};
use siros_openid4vp::cbor::{CborError, Item, Value, decode, encode};
use siros_openid4vp::host::Usable;
use siros_openid4vp::host::{FormatHost, PresentError};
use siros_openid4vp::ids::{ClientId, Nonce, Origin};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{
    Fault, Format, JsonText, Member, MemberValue, Members, OptionIndex,
};
use siros_openid4vp::request::{AgreeableKey, ClientMetadata, ContentEncryption, KeyAgreement};
use siros_openid4vp::resolve::RouteKey;
use siros_openid4vp::routing::VerifierMetadata;
use siros_openid4vp::session::{Session, SessionBinding};
use siros_openid4vp::uri::ResponseUri;
use siros_testkit::cose::cose_encrypt;
use siros_testkit::fixtures::{
    B26_KEY, B26_THUMBPRINT, Held, NONCE, ORIGIN, b26_metadata, dc_api_context, parameters,
    present_option, request_of, unsigned,
};
use siros_testkit::issuer::issue;
use siros_testkit::reading::{
    ModelHandover, ReadError, Rebuild, model_shape, model_value, transcript,
};

siros_testkit::test_host! {
    /// The core's modules and the device MAC's stand-in.
    #[derive(Default)]
    struct MdocHost {
        handles { platform: siros_testkit::TestPlatform => siros_openid4vp::host::Platform }
        zero_sized {
            siros_testkit::TestHaip => siros_openid4vp::host::Haip,
            siros_testkit::TestRequestDecryption => siros_openid4vp::host::RequestDecryption
        }
        optional {
            siros_mdoc::TestDeviceMac => siros_mdoc::DeviceMac
        }
        lacks {}
    }
}

mod device_auth;

const P256: &str = r#"{"kty": "EC", "crv": "P-256", "kid": "reader-p256", "x": "AA", "y": "AQ", "use": "enc", "alg": "ECDH-ES"}"#;
const P384: &str = r#"{"kty": "EC", "crv": "P-384", "kid": "reader-p384", "x": "AA", "y": "AQ"}"#;

/// The presentation of a registration for a query object, with the Verifier's client metadata
/// and the members, over a session sealed to B.2.6's key when `sealed`: the JSON string B.2.5
/// names.
fn present(
    query: &str,
    client_metadata: &str,
    held: &Held,
    members: Vec<(Member, MemberValue)>,
    sealed: bool,
) -> Result<Node<'static>, Fault> {
    present_over(
        &MdocHost::default(),
        query,
        client_metadata,
        held,
        members,
        sealed,
    )
    .map_err(|failed| match failed {
        PresentError::Fault(fault) => fault,
        PresentError::Failed { reason } => panic!("{reason}"),
    })
}

/// [`present`] over a host.
fn present_over<H>(
    host: &H,
    query: &str,
    client_metadata: &str,
    held: &Held,
    members: Vec<(Member, MemberValue)>,
    sealed: bool,
) -> Result<Node<'static>, PresentError>
where
    Mdoc: FormatHost<H>,
{
    let text = parameters(
        &format!(r#"{{"credentials": [{query}]}}"#),
        &format!(r#""client_metadata":{client_metadata}"#),
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let metadata = ClientMetadata::parse(request.client_metadata()).expect("metadata");
    let format = Mdoc::new().expect("format");
    let parsed = FormatHost::<H>::answer(
        &format,
        &request.queries()[0],
        dc_api_context(&request, metadata.vp_formats(&format.id()).cloned()),
    )
    .expect("query");
    let verifier = VerifierMetadata::new(&metadata);
    let b26 = b26_metadata().expect("B.2.6's key");
    let b26 = ClientMetadata::parse(Some(&b26)).expect("metadata");
    let b26 = VerifierMetadata::new(&b26);
    let origin = Origin::parse(ORIGIN).expect("origin");
    let nonce = Nonce::parse(NONCE).expect("nonce");
    let encrypted_to = b26
        .keys()
        .iter()
        .next()
        .filter(|_| sealed)
        .map(|key| RouteKey::new(key, ContentEncryption::A128GCM));
    let session = Session::new(
        SessionBinding::DcApi { origin: &origin },
        &nonce,
        encrypted_to,
        verifier.keys(),
    );
    let credential = held.credential().expect("credential");
    let presentation = present_option(
        parsed.as_ref(),
        Usable::checked(&credential),
        OptionIndex(0),
        &Members::new(members).expect("members"),
        &session,
        host,
    )?;
    Ok(Node::parse(presentation.0.get())
        .expect("JSON")
        .into_owned())
}

/// The registration of a view with its issued IssuerSigned.
fn issued(view: &str) -> Held {
    Held::new("c", "mso_mdoc", view)
        .with_issued()
        .expect("issued")
}

/// The registration of a view with the IssuerSigned issued for another view.
fn issued_for(view: &str, issued: &str) -> Held {
    let mut held = Held::new("c", "mso_mdoc", view);
    held.documents = vec![(
        "mso_mdoc".to_owned(),
        issue(&Node::parse(issued).expect("view")).expect("issued"),
    )];
    held
}

/// The DeviceResponse in the model's shape, its device authentication as the stand-in wrote it.
fn read(presentation: &Node<'_>) -> Node<'static> {
    model_shape(presentation, None).expect("a DeviceResponse")
}

const QUERY: &str =
    r#"{"id": "q", "format": "mso_mdoc", "meta": {"doctype_value": "org.example.card"}}"#;

fn view(device_alg: i64, device_curve: &str) -> String {
    format!(
        r#"{{"type": "org.example.card", "metadata": {{}}, "values": {{}}, "issuer_alg": -7, "issuer_curve": "P-256", "device_alg": {device_alg}, "device_curve": "{device_curve}"}}"#
    )
}

fn document(read: &Node<'_>) -> Node<'static> {
    read.get("documents")
        .and_then(Node::as_array)
        .and_then(|documents| documents.first())
        .cloned()
        .expect("document")
        .into_owned()
}

/// The document's device authentication: its mode, and the Verifier key a MAC was agreed with.
fn device_auth(read: &Node<'_>) -> (String, Option<String>) {
    let document = document(read);
    let auth = document
        .get("deviceSigned")
        .and_then(|signed| signed.get("deviceAuth"))
        .and_then(Node::as_object)
        .expect("deviceAuth");
    let [only] = auth.members() else {
        panic!("one device authentication");
    };
    let proof = only.value.as_str().expect("proof");
    let reader =
        (only.name == "deviceMac").then(|| proof.split(':').nth(2).expect("kid").to_owned());
    (only.name.to_string(), reader)
}

fn rebuild(handover: &ModelHandover) -> Rebuild<'_> {
    Rebuild {
        handover,
        credential: "c",
        device_alg: -7,
    }
}

fn unhex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

// OpenID4VP 1.0 B.2.6.1 and B.2.6.2's example values and hex, as the specification prints them.
const KA_NONCE: &str = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA";
const KA1: &str = "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047";
const KA2: &str = "847818783530395f73616e5f646e733a6578616d706c652e636f6d782b6578633767
426b786a7831726463397564527276654b7653734a4971383061766c58654c486847
7771744158204283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6
bd669047781c68747470733a2f2f6578616d706c652e636f6d2f726573706f6e7365";
const KA3: &str = "82714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494c
efdd9d95240d254b046b11b68013722aad38ac";
const KA4: &str = "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8e
ed494cefdd9d95240d254b046b11b68013722aad38ac";
const KA5: &str = "83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4
212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a";

/// The session B.2.6's examples bind: sealed to B.2.6's key, over `binding`.
fn b26_transcript(binding: SessionBinding<'_>, nonce: &Nonce<'_>) -> SessionTranscript {
    let b26 = b26_metadata().expect("B.2.6's key");
    let b26 = ClientMetadata::parse(Some(&b26)).expect("metadata");
    let b26 = VerifierMetadata::new(&b26);
    let key = b26.keys().iter().next().expect("B.2.6's key");
    let session = Session::new(
        binding,
        nonce,
        Some(RouteKey::new(key, ContentEncryption::A128GCM)),
        b26.keys(),
    );
    SessionTranscript::of(&Handover::of(&session).expect("handover")).expect("transcript")
}

#[test]
fn the_session_transcript_reproduces_the_b_2_6_examples() {
    let key = Node::parse(B26_KEY).expect("jwk");
    let key = AgreeableKey::of(&key).expect("agreeable");
    assert_eq!(
        Thumbprint::of(&key)
            .expect("an EC key")
            .as_bytes()
            .as_slice(),
        unhex(KA1),
        "KA1"
    );
    assert_eq!(KA1, B26_THUMBPRINT);
    let client_id = ClientId::parse("x509_san_dns:example.com").unwrap();
    let response_uri = ResponseUri::parse("https://example.com/response".to_owned()).unwrap();
    let nonce = Nonce::parse(KA_NONCE).unwrap();
    let redirect = b26_transcript(
        SessionBinding::Redirect {
            client_id: &client_id,
            response_uri: &response_uri,
        },
        &nonce,
    );
    let Value::Array(items) = decode(redirect.as_bytes()).unwrap() else {
        panic!("an array")
    };
    // KA3: the handover; KA2: its hash is SHA-256 of B.2.6.1's OpenID4VPHandoverInfo.
    assert_eq!(encode(&items[2]).unwrap(), unhex(KA3), "KA3");
    let Value::Array(handover) = &items[2] else {
        panic!("an array")
    };
    assert_eq!(
        handover[1],
        Value::Bytes(Sha256::digest(unhex(KA2)).to_vec()),
        "KA2"
    );
    assert_eq!(redirect.as_bytes(), unhex(KA4), "KA4");
    let origin = Origin::parse("https://example.com").unwrap();
    let dc_api = b26_transcript(SessionBinding::DcApi { origin: &origin }, &nonce);
    assert_eq!(dc_api.as_bytes(), unhex(KA5), "KA5");
    // The reading writes the transcript apart and reaches B.2.6.2's bytes too.
    let model = ModelHandover {
        origin: "https://example.com".into(),
        nonce: KA_NONCE.into(),
        thumbprint: Some(unhex(KA1).try_into().unwrap()),
    };
    assert_eq!(
        encode(&transcript(&model).unwrap()).unwrap(),
        unhex(KA5),
        "KA5, the reading's"
    );
}

/// RFC 8037 A.3: the thumbprint of an OKP key covers `crv`, `kty` and `x` alone.
#[test]
fn an_okp_thumbprint_follows_rfc_8037_a_3() {
    let key = Node::parse(
        r#"{"kty": "OKP", "crv": "Ed25519", "kid": "k", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
    )
    .expect("jwk");
    let key = AgreeableKey::of(&key).expect("agreeable");
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Thumbprint::of(&key).expect("an OKP key").as_bytes()),
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    );
}

#[test]
fn the_device_authenticates_the_rebuilt_device_authentication() {
    // A device signature and a device MAC, each read by a Verifier that rebuilds
    // DeviceAuthentication from the handover with B.2.6's thumbprint of the key the session is
    // sealed to; another thumbprint or nonce is refused.
    let members = || {
        vec![(
            Member::element("urn:paso:sca:1", "jti"),
            MemberValue::Text("it's".to_owned()),
        )]
    };
    let mac = r#"{"jwks":{"keys":[REPLACE]},"vp_formats_supported":{"mso_mdoc":{"deviceauth_alg_values":[-65537]}}}"#
        .replace("REPLACE", P256);
    let held = issued(&view(-7, "P-256"));
    for (metadata, expected) in [("{}", "deviceSignature"), (mac.as_str(), "deviceMac")] {
        let presentation = present(QUERY, metadata, &held, members(), true).expect("presentation");
        let handover = ModelHandover {
            origin: ORIGIN.to_owned(),
            nonce: NONCE.to_owned(),
            thumbprint: Some(unhex(B26_THUMBPRINT).try_into().unwrap()),
        };
        let read = model_shape(&presentation, Some(rebuild(&handover))).expect("covered");
        assert_eq!(device_auth(&read).0, expected);
        for wrong in [
            ModelHandover {
                thumbprint: None,
                ..handover.clone()
            },
            ModelHandover {
                nonce: format!("{NONCE}x"),
                ..handover.clone()
            },
        ] {
            assert!(matches!(
                model_shape(&presentation, Some(rebuild(&wrong))),
                Err(ReadError::Uncovered { .. })
            ));
        }
    }
}

/// A member's value as the model's shape writes it.
fn shown(value: &MemberValue) -> Node<'static> {
    match value {
        MemberValue::Text(text) => Node::String(text.clone().into()),
        MemberValue::Bytes(bytes) => {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            Node::parse(&format!(r#"{{"bstr": "{hex}"}}"#))
                .expect("bstr")
                .into_owned()
        }
        MemberValue::Json(json) => Node::parse(json.as_str()).expect("json").into_owned(),
        MemberValue::Cbor(item) => {
            model_value(&decode(item.as_bytes()).expect("item")).expect("shape")
        }
    }
}

/// Each (name space, element, value) of a read document's name spaces, in sorted order.
fn elements(document: &Node<'_>, signed: &str) -> Vec<(String, String, Node<'static>)> {
    let spaces = document
        .get(signed)
        .and_then(|s| s.get("nameSpaces"))
        .and_then(Node::as_object)
        .expect("name spaces");
    let mut out: Vec<(String, String, Node<'static>)> = spaces
        .members()
        .iter()
        .flat_map(|ns| {
            ns.value
                .as_object()
                .expect("elements")
                .members()
                .iter()
                .map(|el| {
                    (
                        ns.name.to_string(),
                        el.name.to_string(),
                        el.value.clone().into_owned(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();
    out.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    out
}

#[test]
fn the_document_holds_the_disclosed_elements_and_the_members() {
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let elements_held = [("ns1", "a"), ("ns1", "b"), ("ns2", "c"), ("ns3", "d")];
    for case in 0..200 {
        let mut held: Vec<(&str, &str, i64)> = Vec::new();
        for (ns, el) in elements_held {
            if rng.random_bool(0.7) {
                held.push((ns, el, rng.random_range(-5..5)));
            }
        }
        if held.is_empty() {
            held.push(("ns1", "a", rng.random_range(-5..5)));
        }
        let mut namespaces: Vec<(&str, Vec<String>)> = Vec::new();
        for (ns, el, value) in &held {
            let member = format!("\"{el}\": {value}");
            match namespaces.iter_mut().find(|(known, _)| known == ns) {
                Some((_, members)) => members.push(member),
                None => namespaces.push((ns, vec![member])),
            }
        }
        let values: Vec<String> = namespaces
            .iter()
            .map(|(ns, members)| format!("\"{ns}\": {{{}}}", members.join(", ")))
            .collect();
        // Phase 2 presents an option the credential answers: elements it holds.
        let asked: Vec<(&str, &str)> = held
            .iter()
            .map(|(ns, el, _)| (*ns, *el))
            .filter(|_| rng.random_bool(0.6))
            .collect();
        let asked = if asked.is_empty() {
            vec![(held[0].0, held[0].1)]
        } else {
            asked
        };
        let claims: Vec<String> = asked
            .iter()
            .map(|(ns, el)| format!(r#"{{"path": ["{ns}", "{el}"]}}"#))
            .collect();
        let query = format!(
            r#"{{"id": "q", "format": "mso_mdoc", "meta": {{"doctype_value": "t"}}, "claims": [{}]}}"#,
            claims.join(", ")
        );
        let members: Vec<(Member, MemberValue)> = (0..rng.random_range(0..3))
            .map(|k| {
                let value = match rng.random_range(0..4) {
                    0 => MemberValue::Text(format!("t{k}")),
                    1 => MemberValue::Bytes(vec![k as u8, 0xff]),
                    2 => {
                        MemberValue::Json(JsonText::parse(&format!(r#"[{k}, "x"]"#)).expect("json"))
                    }
                    _ => MemberValue::Cbor(
                        Item::parse(
                            cose_encrypt(
                                KeyAgreement::ECDH_ES,
                                ContentEncryption::A256GCM,
                                "k",
                                &[k as u8],
                            )
                            .expect("COSE_Encrypt"),
                        )
                        .expect("item"),
                    ),
                };
                (
                    Member::Element {
                        namespace: Cow::Borrowed(if k % 2 == 0 { "urn:paso:sca:1" } else { "dm" }),
                        element: Cow::Owned(format!("e{k}")),
                    },
                    value,
                )
            })
            .collect();
        let view = format!(
            r#"{{"type": "t", "metadata": {{}}, "values": {{{}}}, "issuer_alg": -7, "issuer_curve": "P-256", "device_alg": -7, "device_curve": "P-256"}}"#,
            values.join(", ")
        );
        let presentation =
            present(&query, "{}", &issued(&view), members.clone(), false).expect("presentation");
        let read = read(&presentation);
        assert_eq!(read.get("version").and_then(Node::as_str), Some("1.0"));
        let document = document(&read);
        assert_eq!(document.get("docType").and_then(Node::as_str), Some("t"));
        // The issuer-signed name spaces: the asked elements the credential holds.
        let mut want: Vec<(String, String, Node<'static>)> = Vec::new();
        for (ns, el) in &asked {
            if let Some((_, _, value)) = held.iter().find(|(n, e, _)| n == ns && e == el) {
                want.push((
                    (*ns).to_owned(),
                    (*el).to_owned(),
                    Node::integer(i128::from(*value)),
                ));
            }
        }
        want.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        assert_eq!(elements(&document, "issuerSigned"), want, "case {case}");
        // The device-signed name spaces: the members, a byte string as {"bstr": hex}.
        let mut expected: Vec<(String, String, Node<'static>)> = members
            .iter()
            .map(|(member, value)| {
                let Member::Element { namespace, element } = member else {
                    panic!("an element");
                };
                (namespace.to_string(), element.to_string(), shown(value))
            })
            .collect();
        expected.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        assert_eq!(elements(&document, "deviceSigned"), expected, "case {case}");
    }
}

/// The stored IssuerSigned's refusal behind a fault.
fn issued_error(fault: &Fault) -> Option<&IssuedError> {
    fault.source()?.downcast_ref::<IssuedError>()
}

#[test]
fn what_cannot_be_presented_is_a_fault() {
    let good = view(-7, "P-256");
    let text = |value: &str| MemberValue::Text(value.to_owned());
    let refused = |held: &Held, members| present(QUERY, "{}", held, members, false).err();
    // Each fixture beside the one it changes, which presents.
    assert!(refused(&issued(&good), Vec::new()).is_none());
    // The device key's algorithm is a COSE identifier of IANA's registry, its curve one of
    // Table 22.
    for tampered in [
        good.replace("\"device_alg\": -7", "\"device_alg\": \"ES256\""),
        good.replace("\"device_alg\": -7", "\"device_alg\": 12345"),
        good.replace("\"device_curve\": \"P-256\"", "\"device_curve\": \"P-999\""),
        good.replace(", \"device_alg\": -7", ""),
    ] {
        assert!(
            refused(&issued_for(&tampered, &good), Vec::new()).is_some(),
            "{tampered}"
        );
    }
    // DeviceSigned holds data elements.
    assert!(refused(&issued(&good), vec![(Member::claim("jti"), text("j"))]).is_some());
    // The registration holds the IssuerSigned the MSO's docType comes from.
    assert!(refused(&Held::new("c", "mso_mdoc", good.as_str()), Vec::new()).is_some());
    // An element the issuer left out, and an issued value other than the view's.
    let with = |values: &str| good.replace("\"values\": {}", &format!("\"values\": {values}"));
    let claimed = r#"{"id": "q", "format": "mso_mdoc", "meta": {"doctype_value": "org.example.card"}, "claims": [{"path": ["ns", "a"]}]}"#;
    let shown = with(r#"{"ns": {"a": 1}}"#);
    assert!(present(claimed, "{}", &issued(&shown), Vec::new(), false).is_ok());
    let held = issued_for(&shown, &with(r#"{"ns": {"b": 1}}"#));
    let fault = present(claimed, "{}", &held, Vec::new(), false).expect_err("not issued");
    assert!(matches!(
        issued_error(&fault),
        Some(IssuedError::Missing { .. })
    ));
    let held = issued_for(&shown, &with(r#"{"ns": {"a": 2}}"#));
    let fault = present(claimed, "{}", &held, Vec::new(), false).expect_err("another value");
    assert!(matches!(
        issued_error(&fault),
        Some(IssuedError::Differs { .. })
    ));
    // A CBOR member holds one data item with each key once.
    assert!(matches!(
        Item::parse(unhex("a2616101616102")),
        Err(CborError::RepeatedKey(_))
    ));
}
