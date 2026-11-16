//! One refusal per construction rule of `Mdoc::parse` and `Mdoc::disclose`. The honest inputs
//! each fixture edits are accepted: each fixture breaks only its rule.

use sha2::{Digest, Sha256};
use siros_codec::base64url;
use siros_codec::cbor::{CborError, Unsupported, Value};
use siros_codec::member::MemberFault;
use siros_codec::Base64Error;
use siros_mdoc::{
    AlgorithmFault, DeviceKeyFault, DeviceSignedElement, DigestId, DisclosureError, DocTypeFault,
    ElementId, ElementIdentifier, EnvelopeFault, IssuerAuthFault, ItemFault, ItemMember,
    KeyAuthorizationsFault, Mdoc, MdocError, NameFault, NameSpace, NameSpacesFault, PayloadFault,
    ValidityFault, ValueDigestsFault,
};

const DOC_TYPE: &str = "org.example.doc.1";
const NAME_SPACE: &str = "org.example.1";
/// Authorized whole for `DeviceSigned`.
const SIGNED: &str = "org.example.signed.1";
/// Authorized for `tx_hash` alone.
const PARTLY: &str = "org.example.partly.1";

fn text(s: &str) -> Value {
    Value::text(s)
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
}

fn tdate(t: &str) -> Value {
    Value::Tag(0, Box::new(text(t)))
}

fn item_bytes(item: Value) -> Value {
    Value::Tag(24, Box::new(Value::Bytes(item.encode())))
}

fn item(digest_id: u64, identifier: &str, value: Value) -> Value {
    item_bytes(map(vec![
        ("digestID", Value::Unsigned(digest_id)),
        ("random", Value::Bytes(vec![0x11; 16])),
        ("elementIdentifier", text(identifier)),
        ("elementValue", value),
    ]))
}

fn digest(item: &Value) -> Value {
    Value::Bytes(Sha256::digest(item.encode()).to_vec())
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
        .map(|(item, id)| (Value::Unsigned(id), digest(item)))
        .collect();
    Parts {
        items,
        digests,
        digest_algorithm: "SHA-256",
        device_key: vec![
            (Value::Unsigned(1), Value::Unsigned(2)),
            (Value::Negative(0), Value::Unsigned(1)),
            (Value::Negative(1), Value::Bytes(vec![0x01; 32])),
            (Value::Negative(2), Value::Bytes(vec![0x02; 32])),
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
        unprotected: Value::Map(vec![(Value::Unsigned(33), Value::Bytes(vec![0x30, 0x00]))]),
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
    let payload = parts
        .payload
        .clone()
        .unwrap_or_else(|| item_bytes(mso.clone()));
    let issuer_auth = Value::Array(vec![
        parts.protected.clone(),
        parts.unprotected.clone(),
        Value::Bytes(payload.encode()),
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
        ("status", Value::Unsigned(0)),
    ]);
    base64url::encode(&response.encode()).into_string()
}

#[derive(Debug, PartialEq, Eq)]
enum Got {
    Accepted,
    Mdoc(MdocError),
    Disclosure(DisclosureError),
}

fn read(data: &str) -> Got {
    Mdoc::parse(data).map_or_else(Got::Mdoc, |_| Got::Accepted)
}

fn edited(edit: impl FnOnce(&mut Parts)) -> Got {
    let mut parts = honest();
    edit(&mut parts);
    read(&assemble(&parts))
}

fn disclosed(elements: &[(&str, &str)], device_signed: &[(&str, &str)]) -> Got {
    let mdoc = Mdoc::parse(&assemble(&honest())).unwrap();
    let elements: Vec<ElementId> = elements
        .iter()
        .map(|&(name_space, identifier)| ElementId {
            name_space,
            identifier,
        })
        .collect();
    let device_signed = device_signed
        .iter()
        .map(|&(name_space, identifier)| DeviceSignedElement {
            name_space: NameSpace::new(name_space),
            identifier: ElementIdentifier::new(identifier),
            value: Value::Bytes(vec![0x7e; 32]),
        })
        .collect();
    mdoc.disclose(&elements, device_signed)
        .map_or_else(Got::Disclosure, |_| Got::Accepted)
}

const HONEST_SELECTION: [(&str, &str); 1] = [(NAME_SPACE, "given_name")];
const HONEST_DEVICE_SIGNED: [(&str, &str); 2] = [(SIGNED, "payment_hash"), (PARTLY, "tx_hash")];

#[test]
fn each_rule_refuses_its_fixture() {
    let cases: Vec<(&str, Got, Got)> = vec![
        (
            "encoding",
            read("not base64url!"),
            Got::Mdoc(MdocError::Encoding(Base64Error::Alphabet(3))),
        ),
        (
            "cbor",
            read(&base64url::encode(&[0x9f, 0xff]).into_string()),
            Got::Mdoc(MdocError::Cbor(CborError::Unsupported(
                Unsupported::IndefiniteLength,
            ))),
        ),
        (
            "envelope",
            edited(|p| p.documents = 2),
            Got::Mdoc(MdocError::Envelope(EnvelopeFault::Documents(2))),
        ),
        (
            "issuer_auth",
            edited(|p| p.signature = text("r and s")),
            Got::Mdoc(MdocError::IssuerAuth(IssuerAuthFault::Signature)),
        ),
        (
            "algorithm",
            edited(|p| p.protected = Value::Bytes(vec![0xa0])),
            Got::Mdoc(MdocError::Algorithm(AlgorithmFault::Absent)),
        ),
        (
            "x5chain",
            edited(|p| p.unprotected = Value::Map(Vec::new())),
            Got::Mdoc(MdocError::X5chain(MemberFault::Absent)),
        ),
        (
            "payload",
            edited(|p| p.payload = Some(map(vec![("docType", text(DOC_TYPE))]))),
            Got::Mdoc(MdocError::Payload(PayloadFault::NotTagged)),
        ),
        (
            "doc_type",
            edited(|p| p.document_doc_type = "org.example.other.1"),
            Got::Mdoc(MdocError::DocType(DocTypeFault::Mismatch)),
        ),
        (
            "digest_algorithm",
            edited(|p| p.digest_algorithm = "MD5"),
            Got::Mdoc(MdocError::DigestAlgorithm(NameFault::Unknown)),
        ),
        (
            "value_digests",
            edited(|p| p.digests[0].1 = Value::Bytes(vec![0; 31])),
            Got::Mdoc(MdocError::ValueDigests(ValueDigestsFault::DigestLength(
                NameSpace::new(NAME_SPACE),
                DigestId::new(0),
                31,
            ))),
        ),
        (
            "device_key",
            edited(|p| p.device_key[1].1 = Value::Unsigned(2)),
            Got::Mdoc(MdocError::DeviceKey(DeviceKeyFault::Curve)),
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
                ])
            }),
            Got::Mdoc(MdocError::KeyAuthorizations(
                KeyAuthorizationsFault::Overlap(NameSpace::new(SIGNED)),
            )),
        ),
        (
            "validity",
            edited(|p| p.validity[2] = p.validity[1]),
            Got::Mdoc(MdocError::Validity(ValidityFault::Order)),
        ),
        (
            "name_spaces",
            edited(|p| p.items.clear()),
            Got::Mdoc(MdocError::NameSpaces(NameSpacesFault::Items(
                NameSpace::new(NAME_SPACE),
                MemberFault::Empty,
            ))),
        ),
        (
            "item",
            edited(|p| {
                p.items[0] = item_bytes(map(vec![
                    ("digestID", Value::Unsigned(0)),
                    ("elementIdentifier", text("given_name")),
                    ("elementValue", text("Ada")),
                ]))
            }),
            Got::Mdoc(MdocError::Item(ItemFault::Member(ItemMember::Random))),
        ),
        (
            "repeated_element",
            edited(|p| {
                let again = item(2, "given_name", text("Augusta"));
                p.digests.push((Value::Unsigned(2), digest(&again)));
                p.items.push(again);
            }),
            Got::Mdoc(MdocError::RepeatedElement),
        ),
        (
            "item_digest",
            edited(|p| p.digests[1].1 = Value::Bytes(vec![0; 32])),
            Got::Mdoc(MdocError::ItemDigest),
        ),
        (
            "unknown_element",
            disclosed(&[(NAME_SPACE, "birth_date")], &[]),
            Got::Disclosure(DisclosureError::UnknownElement),
        ),
        (
            "repeated_selection",
            disclosed(&[HONEST_SELECTION[0], HONEST_SELECTION[0]], &[]),
            Got::Disclosure(DisclosureError::RepeatedSelection),
        ),
        (
            "unauthorized_device_element",
            disclosed(&HONEST_SELECTION, &[(PARTLY, "amount")]),
            Got::Disclosure(DisclosureError::Unauthorized),
        ),
        (
            "repeated_device_element",
            disclosed(
                &HONEST_SELECTION,
                &[HONEST_DEVICE_SIGNED[0], HONEST_DEVICE_SIGNED[0]],
            ),
            Got::Disclosure(DisclosureError::RepeatedDeviceElement),
        ),
    ];
    assert_eq!(edited(|_| {}), Got::Accepted);
    assert_eq!(
        disclosed(&HONEST_SELECTION, &HONEST_DEVICE_SIGNED),
        Got::Accepted
    );
    let failures: Vec<String> = cases
        .into_iter()
        .filter(|(_, got, want)| got != want)
        .map(|(name, got, want)| format!("{name}: got {got:?}, want {want:?}"))
        .collect();
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
