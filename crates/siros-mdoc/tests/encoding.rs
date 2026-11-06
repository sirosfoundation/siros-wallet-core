//! ISO/IEC 18013-5's CBOR and COSE as siros-mdoc writes them: the Sig_structure and MAC_structure
//! the host's modules authenticate against RFC 9052's built by hand, the stored IssuerSigned
//! against the MSO's digests and its refusals, and the presentation read against the reference
//! model's own.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use siros_mdoc::Mdoc;
use siros_mdoc::issuer_signed::{Disclosed, IssuedError, IssuerSigned};
use siros_mdoc::stored::{ElementIdentifier, NameSpace};
use siros_mdoc::{DeviceMac, Mac, SessionTranscriptBytes, TestDeviceMac};
use siros_openid4vp::cbor::cose::CoseShape;
use siros_openid4vp::cbor::cose::coset::iana;
use siros_openid4vp::cbor::cose::coset::{AsCborValue, CoseSign1, CoseSign1Builder, HeaderBuilder};
use siros_openid4vp::cbor::{Value, decode, embedded, encode};
use siros_openid4vp::host::{
    CoreHost, FormatHost, Haip, Has, Held, MayHave, Platform, SealedJwe, SignFailed, Signature,
    Usable,
};
use siros_openid4vp::ids::CredentialId;
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{Fault, Members};
use siros_openid4vp::request::{AgreeableKey, ContentEncryption};
use siros_testkit::fixtures::{
    B26_THUMBPRINT, Held as Registered, NONCE, ORIGIN, parameters, present_option, unsigned,
};
use siros_testkit::issuer::issue;
use siros_testkit::oracle::member;
use siros_testkit::probe::{dc_api, read_phase_two, sealed_to_b26};
use siros_testkit::reading::{ModelHandover, ReadError, Rebuild, covered, model_shape, transcript};
use siros_testkit::{TestChoice, TestHaip, TestPlatform};
use std::cell::RefCell;

/// The data the keystore signed and the device MAC module MACed, recorded; each delegates to its
/// stand-in.
#[derive(Default)]
struct Records {
    signed: RefCell<Vec<Vec<u8>>>,
    maced: RefCell<Vec<Vec<u8>>>,
}

impl Haip for Records {
    fn verifies(&self) -> siros_openid4vp::jose::JwsAlgorithms {
        TestHaip.verifies()
    }
    fn agreements(&self) -> siros_openid4vp::request::Agreements {
        TestHaip.agreements()
    }
    fn verify(
        &self,
        key: &siros_openid4vp::jose::VerificationKey,
        signed: &siros_openid4vp::jose::Signed<'_>,
    ) -> Result<(), siros_openid4vp::host::SignatureInvalid> {
        TestHaip.verify(key, signed)
    }
    fn sign(&self, credential: &CredentialId<'_>, data: &[u8]) -> Result<Signature, SignFailed> {
        self.signed.borrow_mut().push(data.to_vec());
        TestHaip.sign(credential, data)
    }
    fn encrypt_jwe(
        &self,
        key: &AgreeableKey<'_>,
        enc: ContentEncryption<'_>,
        plaintext: &[u8],
    ) -> Result<SealedJwe, Fault> {
        TestHaip.encrypt_jwe(key, enc, plaintext)
    }
}

impl DeviceMac for Records {
    fn mac(
        &self,
        credential: &CredentialId<'_>,
        reader: &AgreeableKey<'_>,
        transcript: &SessionTranscriptBytes,
        data: &[u8],
    ) -> Result<Mac, Fault> {
        self.maced.borrow_mut().push(data.to_vec());
        TestDeviceMac.mac(credential, reader, transcript, data)
    }
}

/// The host recording what its modules authenticate: one leaked [`Records`] per host, which a
/// `Held` slot gives as `&'static`.
struct Recording {
    platform: TestPlatform,
    records: &'static Records,
    mac: Held<dyn DeviceMac>,
}

impl Recording {
    fn new() -> Self {
        let records: &'static Records = Box::leak(Box::default());
        Self {
            platform: TestPlatform::default(),
            records,
            mac: Held::new(records),
        }
    }
}

impl Has<dyn Platform> for Recording {
    fn module(&self) -> &(dyn Platform + 'static) {
        &self.platform
    }
}

impl Has<dyn Haip> for Recording {
    fn module(&self) -> &(dyn Haip + 'static) {
        self.records
    }
}

impl Has<dyn siros_openid4vp::host::RequestDecryption> for Recording {
    fn module(&self) -> &(dyn siros_openid4vp::host::RequestDecryption + 'static) {
        &siros_testkit::TestRequestDecryption
    }
}

impl MayHave<dyn DeviceMac> for Recording {
    type Slot = Held<dyn DeviceMac>;

    fn slot(&self) -> &Self::Slot {
        &self.mac
    }
}

/// The presentation of a registration for a query, the Verifier's client metadata and the
/// members, over the DC API, the session sealed to B.2.6's key when `sealed`.
fn present<H>(
    query: &str,
    client_metadata: &str,
    held: &Registered,
    members: Members,
    sealed: bool,
    host: &H,
) -> Node<'static>
where
    H: CoreHost + Has<dyn Haip> + MayHave<dyn DeviceMac> + 'static,
{
    let (client_metadata, choice) = if sealed {
        sealed_to_b26(client_metadata).expect("B.2.6's key")
    } else {
        (client_metadata.to_owned(), TestChoice::Plain)
    };
    let text = parameters(
        &format!(r#"{{"credentials": [{query}]}}"#),
        &format!(r#""client_metadata":{client_metadata}"#),
    );
    let received = unsigned(&text).expect("received");
    let held = held.clone();
    read_phase_two(
        &received,
        "mso_mdoc",
        dc_api(choice),
        host,
        move |phase_two| {
            let format = Mdoc::new().expect("format");
            let parsed = FormatHost::<H>::answer(&format, phase_two.query, phase_two.context)
                .expect("query");
            let credential = held.credential().expect("credential");
            let presentation = present_option(
                parsed.as_ref(),
                Usable::checked(&credential),
                0,
                &members,
                phase_two.session,
                phase_two.host,
            )
            .expect("presentation");
            Node::parse(presentation.as_str())
                .expect("JSON")
                .into_owned()
        },
    )
    .expect("the flow reaches the format")
}

/// A map member by its text key.
fn get<'v>(map: &'v Value, name: &str) -> &'v Value {
    let Value::Map(pairs) = map else {
        panic!("{name}: no map")
    };
    &pairs
        .iter()
        .find(|(key, _)| *key == Value::Text(name.to_owned()))
        .unwrap_or_else(|| panic!("no {name}"))
        .1
}

const VIEW: &str = r#"{"type": "org.example.t", "metadata": {}, "values": {"ns": {"a": 1}}, "issuer_alg": -7, "issuer_curve": "P-256", "device_alg": -7, "device_curve": "P-256"}"#;
const QUERY: &str = r#"{"id": "q", "format": "mso_mdoc", "meta": {"doctype_value": "org.example.t"}, "claims": [{"path": ["ns", "a"]}]}"#;
const P256: &str = r#"{"kty": "EC", "crv": "P-256", "kid": "reader-p256", "x": "AA", "y": "AQ"}"#;

#[test]
fn the_host_authenticates_rfc_9052s_structures() {
    let held = Registered::new("c", "mso_mdoc", VIEW)
        .with_issued()
        .expect("issued");
    let mac = format!(
        r#"{{"jwks": {{"keys": [{P256}]}}, "vp_formats_supported": {{"mso_mdoc": {{"deviceauth_alg_values": [-65537]}}}}}}"#
    );
    // ({1: -7} is a1 01 26, {1: 5} a1 01 05.)
    for (metadata, context, protected) in [
        ("{}", "Signature1", "a10126"),
        (mac.as_str(), "MAC0", "a10105"),
    ] {
        let host = Recording::new();
        let presentation = present(QUERY, metadata, &held, Members::none(), false, &host);
        let bytes = URL_SAFE_NO_PAD
            .decode(presentation.as_str().expect("text"))
            .expect("base64url");
        let response = decode(&bytes).expect("DeviceResponse");
        let Value::Array(documents) = get(&response, "documents") else {
            panic!("documents")
        };
        let device = get(get(&documents[0], "deviceSigned"), "nameSpaces").clone();
        // ISO/IEC 18013-5 §9.1.3.4 DeviceAuthenticationBytes, built by hand from the handover.
        let handover = ModelHandover {
            origin: ORIGIN.to_owned(),
            nonce: NONCE.to_owned(),
            thumbprint: None,
        };
        let authentication = Value::Array(vec![
            Value::Text("DeviceAuthentication".into()),
            transcript(&handover).expect("transcript"),
            Value::Text("org.example.t".into()),
            device,
        ]);
        let detached = encode(&embedded(encode(&authentication).unwrap())).unwrap();
        // RFC 9052 §4.4 and §6.3: [context, body_protected, external_aad, payload].
        let by_hand = encode(&Value::Array(vec![
            Value::Text(context.into()),
            Value::Bytes(hex(protected)),
            Value::Bytes(Vec::new()),
            Value::Bytes(detached),
        ]))
        .unwrap();
        let recorded = if context == "MAC0" {
            host.records.maced.take()
        } else {
            host.records.signed.take()
        };
        assert_eq!(recorded, vec![by_hand], "{context}");
    }
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|k| u8::from_str_radix(&text[k..k + 2], 16).unwrap())
        .collect()
}

#[test]
fn the_presented_items_are_the_issued_ones_the_mso_digests() {
    let view = Node::parse(
        r#"{"type": "org.example.t", "metadata": {}, "values": {"ns1": {"a": 1, "b": "x"}, "ns2": {"c": [1, 2.5, null]}}, "issuer_alg": -7, "issuer_curve": "P-256", "device_alg": -7, "device_curve": "P-256"}"#,
    )
    .unwrap();
    let issued = issue(&view).unwrap();
    let stored = IssuerSigned::read(&issued).unwrap();
    let values = view.get("values").unwrap();
    let shown = |namespace, element| Disclosed {
        namespace: NameSpace::new(namespace),
        element: ElementIdentifier::new(element),
        shown: values.get(namespace).unwrap().get(element).unwrap(),
    };
    let disclosed = stored
        .disclose(&[shown("ns1", "a"), shown("ns2", "c"), shown("ns1", "b")])
        .unwrap();
    // Each presented item's tagged bytes digest to the MSO's value digest of its digestID.
    let issuer_auth = CoseSign1::from_cbor_value(get(&disclosed, "issuerAuth").clone()).unwrap();
    let Value::Tag(24, mso) = decode(&issuer_auth.payload.unwrap()).unwrap() else {
        panic!("tag 24")
    };
    let Value::Bytes(mso) = *mso else {
        panic!("bytes")
    };
    let digests = get(&decode(&mso).unwrap(), "valueDigests").clone();
    let Value::Map(spaces) = get(&disclosed, "nameSpaces") else {
        panic!("nameSpaces")
    };
    let mut covered_items = 0;
    for (namespace, items) in spaces {
        let Value::Text(namespace) = namespace else {
            panic!("a name space")
        };
        let Value::Array(items) = items else {
            panic!("items")
        };
        for tagged in items {
            let Value::Tag(24, inner) = tagged else {
                panic!("tag 24")
            };
            let Value::Bytes(bytes) = inner.as_ref() else {
                panic!("bytes")
            };
            let item = decode(bytes).unwrap();
            let Value::Map(ids) = get(&digests, namespace) else {
                panic!("digests")
            };
            let digest_id = get(&item, "digestID");
            let want = &ids.iter().find(|(id, _)| id == digest_id).unwrap().1;
            assert_eq!(
                *want,
                Value::Bytes(Sha256::digest(encode(tagged).unwrap()).to_vec())
            );
            covered_items += 1;
        }
    }
    assert_eq!(covered_items, 3);
    // Refusals: a value other than the view's, an element never issued, an unknown member, a
    // label in both of IssuerAuth's buckets, a payload that is no MSO.
    let other = Node::parse("2").unwrap();
    let wrong = |element| Disclosed {
        namespace: NameSpace::new("ns1"),
        element: ElementIdentifier::new(element),
        shown: &other,
    };
    assert!(matches!(
        stored.disclose(&[wrong("a")]),
        Err(IssuedError::Differs { .. })
    ));
    assert!(matches!(
        stored.disclose(&[wrong("z")]),
        Err(IssuedError::Missing { .. })
    ));
    let Value::Map(mut members) = decode(&issued).unwrap() else {
        panic!("a map")
    };
    members.push((Value::Text("errors".into()), Value::Null));
    assert!(matches!(
        IssuerSigned::read(&encode(&Value::Map(members.clone())).unwrap()),
        Err(IssuedError::Shape(_))
    ));
    let _errors = members.pop();
    members[1].1 = CoseSign1Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .build(),
        )
        .unprotected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .build(),
        )
        .payload(vec![1])
        .signature(vec![2])
        .build()
        .to_cbor_value()
        .unwrap();
    assert!(matches!(
        IssuerSigned::read(&encode(&Value::Map(members.clone())).unwrap()),
        Err(IssuedError::IssuerAuth(CoseShape::BothBuckets(_)))
    ));
    let mut no_mso = members.clone();
    no_mso[1].1 = CoseSign1Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .build(),
        )
        .payload(vec![1])
        .signature(vec![2])
        .build()
        .to_cbor_value()
        .unwrap();
    assert!(matches!(
        IssuerSigned::read(&encode(&Value::Map(no_mso)).unwrap()),
        Err(IssuedError::Shape(_))
    ));
}

#[test]
fn the_reading_equals_the_frozen_models_presentations() {
    // oracle/export_mdoc_cases.py's run of the reference model's fmt_mdoc.present.
    let lines = include_str!("data/model_mdoc.jsonl");
    for line in lines.lines() {
        let case: Json = serde_json::from_str(line).unwrap();
        let name = case["name"].as_str().unwrap();
        let view_text = case["view"].as_str().unwrap();
        let view = Node::parse(view_text).unwrap();
        let claims: Vec<String> = view
            .get("values")
            .and_then(Node::as_object)
            .unwrap()
            .members()
            .iter()
            .flat_map(|ns| {
                ns.value
                    .as_object()
                    .unwrap()
                    .names()
                    .map(|el| format!(r#"["{}", "{el}"]"#, ns.name))
                    .collect::<Vec<_>>()
            })
            .enumerate()
            .map(|(k, path)| format!(r#"{{"id": "k{k}", "path": {path}}}"#))
            .collect();
        let query = format!(
            r#"{{"id": "q", "format": "mso_mdoc", "meta": {{"doctype_value": "org.example.t"}}, "claims": [{}]}}"#,
            claims.join(", ")
        );
        let members = Members::new(
            case["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(|written| member(written).unwrap())
                .collect(),
        )
        .unwrap();
        // The model binds a thumbprint of no key; the port's session is sealed to B.2.6's key in
        // its place, which the rebuilt handover binds by B.2.6's thumbprint.
        let sealed = case["handover"][2].is_string();
        let thumbprint = sealed.then(|| <[u8; 32]>::try_from(hex(B26_THUMBPRINT)).unwrap());
        let held = Registered::new("c1", "mso_mdoc", view_text)
            .with_issued()
            .unwrap();
        let port = present(
            &query,
            case["metadata"].as_str().unwrap(),
            &held,
            members,
            sealed,
            &Recording::new(),
        );
        let device_alg = case["view"]
            .as_str()
            .and_then(|v| serde_json::from_str::<Json>(v).ok())
            .and_then(|v| v["device_alg"].as_i64())
            .unwrap();
        let handover = ModelHandover {
            origin: case["handover"][0].as_str().unwrap().to_owned(),
            nonce: case["handover"][1].as_str().unwrap().to_owned(),
            thumbprint,
        };
        let rebuild = |handover| Rebuild {
            handover,
            credential: "c1",
            device_alg,
        };
        let read = model_shape(&port, Some(rebuild(&handover))).unwrap();
        // The model's presentation in its own member order, read with the core's parser.
        let ordered = Node::parse(line).unwrap();
        let model = covered(ordered.get("presentation").unwrap()).unwrap();
        assert_eq!(
            read.python_compact().to_string(),
            model.python_compact().to_string(),
            "{name}"
        );
        // Another nonce is refused: the device authentication covers the transcript.
        let wrong = ModelHandover {
            nonce: format!("{}x", handover.nonce),
            ..handover.clone()
        };
        assert!(
            matches!(
                model_shape(&port, Some(rebuild(&wrong))),
                Err(ReadError::Uncovered { .. })
            ),
            "{name}"
        );
    }
}
