//! One refusal per construction rule of `StoredMdoc::parse` (ISO/IEC 18013-5, 8.3.2.1.2.2 and
//! 9.1.2). The honest credential the fixtures edit is accepted: each fixture breaks only its rule.

use base64::DecodeError;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use siros_mdoc::registration::{Registered, RegistrationError, Resolved};
use siros_mdoc::stored::{
    AlgorithmFault, CborError, DeviceKeyFault, DigestId, DocTypeFault, EnvelopeFault,
    IssuerAuthFault, ItemFault, ItemMember, KeyAuthorizationsFault, MdocError, MemberFault,
    NameFault, NameSpace, NameSpacesFault, PayloadFault, StoredMdoc, ValidityFault,
    ValueDigestsFault,
};
use siros_openid4vp::cbor::{self, Value};
use siros_openid4vp::claims::kit::{IssuedMetadata, MergeError};
use siros_openid4vp::json::Node;

const DOC_TYPE: &str = "org.example.doc.1";
const NAME_SPACE: &str = "org.example.1";
/// Authorized whole for `DeviceSigned`.
const SIGNED: &str = "org.example.signed.1";
/// Authorized for `tx_hash` alone.
const PARTLY: &str = "org.example.partly.1";

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn int(n: i64) -> Value {
    Value::Integer(n.into())
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
}

fn tdate(t: &str) -> Value {
    Value::Tag(0, Box::new(text(t)))
}

fn encode(value: &Value) -> Vec<u8> {
    cbor::encode(value).unwrap()
}

fn item_bytes(item: &Value) -> Value {
    Value::Tag(24, Box::new(Value::Bytes(encode(item))))
}

fn item(digest_id: i64, identifier: &str, value: Value) -> Value {
    item_bytes(&map(vec![
        ("digestID", int(digest_id)),
        ("random", Value::Bytes(vec![0x11; 16])),
        ("elementIdentifier", text(identifier)),
        ("elementValue", value),
    ]))
}

/// SHA-256 over the encoded `IssuerSignedItemBytes`, tag included (9.1.2.5).
fn digest(item: &Value) -> Value {
    Value::Bytes(Sha256::digest(encode(item)).to_vec())
}

/// An honest credential in parts, for the fixtures to edit.
struct Parts {
    items: Vec<Value>,
    digests: Vec<(Value, Value)>,
    digest_algorithm: &'static str,
    device_key: Vec<(Value, Value)>,
    key_authorizations: Value,
    validity: [&'static str; 3],
    protected: Value,
    unprotected: Value,
    payload: Option<Value>,
    signature: Value,
    document_doc_type: &'static str,
    documents: usize,
}

fn honest() -> Parts {
    let items = vec![
        item(0, "given_name", text("Ada")),
        item(1, "family_name", text("Lovelace")),
    ];
    let digests = items
        .iter()
        .zip(0..)
        .map(|(item, id)| (int(id), digest(item)))
        .collect();
    Parts {
        items,
        digests,
        digest_algorithm: "SHA-256",
        device_key: vec![
            (int(1), int(2)),
            (int(-1), int(1)),
            (int(-2), Value::Bytes(vec![0x01; 32])),
            (int(-3), Value::Bytes(vec![0x02; 32])),
        ],
        key_authorizations: map(vec![
            ("nameSpaces", Value::Array(vec![text(SIGNED)])),
            (
                "dataElements",
                Value::Map(vec![(text(PARTLY), Value::Array(vec![text("tx_hash")]))]),
            ),
        ]),
        validity: [
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
        ],
        protected: Value::Bytes(vec![0xa1, 0x01, 0x26]),
        unprotected: Value::Map(vec![(int(33), Value::Bytes(vec![0x30, 0x00]))]),
        payload: None,
        signature: Value::Bytes(vec![0; 64]),
        document_doc_type: DOC_TYPE,
        documents: 1,
    }
}

/// A `DeviceResponse` of `parts.documents` copies of the document, base64url.
fn assemble(parts: &Parts) -> String {
    let [signed, valid_from, valid_until] = parts.validity;
    let mso = map(vec![
        ("version", text("1.0")),
        ("digestAlgorithm", text(parts.digest_algorithm)),
        (
            "valueDigests",
            Value::Map(vec![(text(NAME_SPACE), Value::Map(parts.digests.clone()))]),
        ),
        (
            "deviceKeyInfo",
            map(vec![
                ("deviceKey", Value::Map(parts.device_key.clone())),
                ("keyAuthorizations", parts.key_authorizations.clone()),
            ]),
        ),
        ("docType", text(DOC_TYPE)),
        (
            "validityInfo",
            map(vec![
                ("signed", tdate(signed)),
                ("validFrom", tdate(valid_from)),
                ("validUntil", tdate(valid_until)),
            ]),
        ),
    ]);
    let payload = parts.payload.clone().unwrap_or_else(|| item_bytes(&mso));
    let issuer_auth = Value::Array(vec![
        parts.protected.clone(),
        parts.unprotected.clone(),
        Value::Bytes(encode(&payload)),
        parts.signature.clone(),
    ]);
    let issuer_signed = map(vec![
        (
            "nameSpaces",
            Value::Map(vec![(text(NAME_SPACE), Value::Array(parts.items.clone()))]),
        ),
        ("issuerAuth", issuer_auth),
    ]);
    let document = map(vec![
        ("docType", text(parts.document_doc_type)),
        ("issuerSigned", issuer_signed),
    ]);
    let response = map(vec![
        ("version", text("1.0")),
        ("documents", Value::Array(vec![document; parts.documents])),
        ("status", int(0)),
    ]);
    URL_SAFE_NO_PAD.encode(encode(&response))
}

fn read(data: &str) -> Result<(), MdocError> {
    StoredMdoc::parse(data).map(|_| ())
}

fn edited(edit: impl FnOnce(&mut Parts)) -> Result<(), MdocError> {
    let mut parts = honest();
    edit(&mut parts);
    read(&assemble(&parts))
}

#[test]
fn each_rule_refuses_its_fixture() {
    let cases: Vec<(&str, Result<(), MdocError>, MdocError)> = vec![
        (
            "encoding",
            read("not base64url!"),
            MdocError::Encoding(DecodeError::InvalidByte(3, b' ')),
        ),
        (
            "cbor",
            // Additional information 28 is reserved: no well-formed item (RFC 8949, 3).
            read(&URL_SAFE_NO_PAD.encode([0x1c])),
            MdocError::Cbor(CborError::Malformed),
        ),
        (
            "envelope",
            edited(|p| p.documents = 2),
            MdocError::Envelope(EnvelopeFault::Documents(2)),
        ),
        (
            "issuer_auth",
            edited(|p| p.signature = text("r and s")),
            MdocError::IssuerAuth(IssuerAuthFault::Signature),
        ),
        (
            "algorithm",
            edited(|p| p.protected = Value::Bytes(vec![0xa0])),
            MdocError::Algorithm(AlgorithmFault::Absent),
        ),
        (
            "x5chain",
            edited(|p| p.unprotected = Value::Map(Vec::new())),
            MdocError::X5chain(MemberFault::Absent),
        ),
        (
            "payload",
            edited(|p| p.payload = Some(map(vec![("docType", text(DOC_TYPE))]))),
            MdocError::Payload(PayloadFault::NotTagged),
        ),
        (
            "doc_type",
            edited(|p| p.document_doc_type = "org.example.other.1"),
            MdocError::DocType(DocTypeFault::Mismatch),
        ),
        (
            "digest_algorithm",
            edited(|p| p.digest_algorithm = "MD5"),
            MdocError::DigestAlgorithm(NameFault::Unknown),
        ),
        (
            "value_digests",
            edited(|p| p.digests[0].1 = Value::Bytes(vec![0; 31])),
            MdocError::ValueDigests(ValueDigestsFault::DigestLength(
                NameSpace::new(NAME_SPACE),
                DigestId::new(0),
                31,
            )),
        ),
        (
            "device_key",
            edited(|p| p.device_key[1].1 = int(99)),
            MdocError::DeviceKey(DeviceKeyFault::Curve),
        ),
        (
            "device_key_type",
            edited(|p| p.device_key[0].1 = int(1)),
            MdocError::DeviceKey(DeviceKeyFault::KeyType),
        ),
        (
            "device_key_coordinate",
            edited(|p| p.device_key[3].1 = Value::Bytes(vec![0x02; 31])),
            MdocError::DeviceKey(DeviceKeyFault::Coordinate),
        ),
        (
            "key_authorizations",
            edited(|p| {
                p.key_authorizations = map(vec![
                    ("nameSpaces", Value::Array(vec![text(SIGNED)])),
                    (
                        "dataElements",
                        Value::Map(vec![(text(SIGNED), Value::Array(vec![text("tx_hash")]))]),
                    ),
                ]);
            }),
            MdocError::KeyAuthorizations(KeyAuthorizationsFault::Overlap(NameSpace::new(SIGNED))),
        ),
        (
            "validity",
            edited(|p| p.validity[2] = p.validity[1]),
            MdocError::Validity(ValidityFault::Order),
        ),
        (
            "name_spaces",
            edited(|p| p.items.clear()),
            MdocError::NameSpaces(NameSpacesFault::Items(
                NameSpace::new(NAME_SPACE),
                MemberFault::Empty,
            )),
        ),
        (
            "item",
            edited(|p| {
                p.items[0] = item_bytes(&map(vec![
                    ("digestID", int(0)),
                    ("elementIdentifier", text("given_name")),
                    ("elementValue", text("Ada")),
                ]));
            }),
            MdocError::Item(ItemFault::Member(ItemMember::Random)),
        ),
        (
            "repeated_element",
            edited(|p| {
                let again = item(2, "given_name", text("Augusta"));
                p.digests.push((int(2), digest(&again)));
                p.items.push(again);
            }),
            MdocError::RepeatedElement,
        ),
        (
            "item_digest",
            edited(|p| p.digests[1].1 = Value::Bytes(vec![0; 32])),
            MdocError::ItemDigest,
        ),
    ];
    assert_eq!(edited(|_| {}), Ok(()));
    let failures: Vec<String> = cases
        .into_iter()
        .filter(|(_, got, want)| got.as_ref().err() != Some(want))
        .map(|(name, got, want)| format!("{name}: got {got:?}, want {want:?}"))
        .collect();
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// ISO/IEC 18013-5 Table 22's curves, by their COSE labels and key types (RFC 9053 §7.1), with the
/// algorithm the table gives each; a stated `alg` (label 3) comes first.
#[test]
fn each_table_22_curve_reads_with_its_algorithm() {
    // (crv, kty, name, alg).
    let rows = [
        (1, 2, "P-256", -7),
        (2, 2, "P-384", -35),
        (3, 2, "P-521", -36),
        (4, 1, "X25519", -25),
        (5, 1, "X448", -25),
        (6, 1, "Ed25519", -8),
        (7, 1, "Ed448", -8),
        (256, 2, "brainpoolP256r1", -7),
        (257, 2, "brainpoolP320r1", -35),
        (258, 2, "brainpoolP384r1", -35),
        (259, 2, "brainpoolP512r1", -36),
    ];
    for (crv, kty, name, alg) in rows {
        let mut parts = honest();
        parts.device_key[0].1 = int(kty);
        parts.device_key[1].1 = int(crv);
        let mdoc = StoredMdoc::parse(&assemble(&parts)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let key = mdoc.mso().device_key();
        assert_eq!((key.curve(), key.algorithm().value()), (name, alg));
    }
    let mut parts = honest();
    parts.device_key.push((int(3), int(-9)));
    let mdoc = StoredMdoc::parse(&assemble(&parts)).unwrap();
    assert_eq!(mdoc.mso().device_key().algorithm().value(), -9);
}

/// What makes no view: a text of no stored mdoc, metadata of no object, an element whose value has
/// no JSON form (RFC 8949 §6.1).
#[test]
fn registration_refusals() {
    let none = Resolved::default();
    assert!(matches!(
        Registered::of("not base64url!", &none),
        Err(RegistrationError::Stored(MdocError::Encoding(_)))
    ));
    let metadata = Resolved {
        issued: IssuedMetadata {
            configuration: Some(Node::parse("[]").unwrap()),
            ..IssuedMetadata::default()
        },
        ..Resolved::default()
    };
    assert!(matches!(
        Registered::of(&assemble(&honest()), &metadata),
        Err(RegistrationError::Metadata {
            cause: MergeError::ConfigurationNotObject
        })
    ));
    let mut parts = honest();
    parts.items[0] = item(0, "given_name", Value::Map(vec![(int(1), int(2))]));
    parts.digests[0].1 = digest(&parts.items[0]);
    assert!(matches!(
        Registered::of(&assemble(&parts), &none),
        Err(RegistrationError::Value(cbor::CborError::Key(_)))
    ));
}
