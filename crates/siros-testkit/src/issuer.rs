//! The issuer stand-in: the IssuerSigned (ISO/IEC 18013-5 §8.3.2.1.2.2) of a credential view
//! the reference model wrote, which a registration holds as its `mso_mdoc` document. One
//! IssuerSignedItem per value (RFC 8949 §6.2 of the JSON), and an IssuerAuth whose
//! MobileSecurityObject digests each item.

use sha2::{Digest, Sha256};
use siros_explain::Explain;
use siros_openid4vp::cbor::cose::coset::iana::{self, EnumI64};
use siros_openid4vp::cbor::cose::coset::{self, AsCborValue, CoseSign1Builder, HeaderBuilder};
use siros_openid4vp::cbor::{self, CborError, Value};
use siros_openid4vp::json::Node;

use crate::host::digest_prefix;

/// The document key under which a registration holds its IssuerSigned.
pub const DOCUMENT: &str = "mso_mdoc";

/// Why a view cannot be issued.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "testkit.issue")]
pub enum IssueError {
    /// The view lacks a member, or holds one of another type.
    #[error("the view's {0}")]
    View(#[explain(name = "member")] &'static str),
    /// The view repeats a member name.
    #[error(transparent)]
    Json(#[from] siros_openid4vp::json::JsonError),
    /// A value does not convert or encode.
    #[error("a value of the view")]
    Cbor(
        #[from]
        #[explain(name = "cause")]
        CborError,
    ),
    /// coset could not write IssuerAuth.
    #[error("IssuerAuth")]
    Cose(
        #[source]
        #[explain(skip)]
        coset::CoseError,
    ),
}

/// `#6.24(bstr .cbor item)`: an embedded data item.
fn embedded(bytes: Vec<u8>) -> Value {
    Value::Tag(24, Box::new(Value::Bytes(bytes)))
}

/// RFC 9053 §7.1's key type and curve of a curve name the view states, as a COSE_Key.
fn device_key(curve: &str) -> Result<Vec<(Value, Value)>, IssueError> {
    let (kty, crv) = match curve {
        "P-256" => (iana::KeyType::EC2, iana::EllipticCurve::P_256),
        "P-384" => (iana::KeyType::EC2, iana::EllipticCurve::P_384),
        "P-521" => (iana::KeyType::EC2, iana::EllipticCurve::P_521),
        "X25519" => (iana::KeyType::OKP, iana::EllipticCurve::X25519),
        "X448" => (iana::KeyType::OKP, iana::EllipticCurve::X448),
        "Ed25519" => (iana::KeyType::OKP, iana::EllipticCurve::Ed25519),
        "Ed448" => (iana::KeyType::OKP, iana::EllipticCurve::Ed448),
        "brainpoolP256r1" => (iana::KeyType::EC2, iana::EllipticCurve::BrainpoolP256R1),
        "brainpoolP320r1" => (iana::KeyType::EC2, iana::EllipticCurve::BrainpoolP320R1),
        "brainpoolP384r1" => (iana::KeyType::EC2, iana::EllipticCurve::BrainpoolP384R1),
        "brainpoolP512r1" => (iana::KeyType::EC2, iana::EllipticCurve::BrainpoolP512R1),
        _ => return Err(IssueError::View("device_curve")),
    };
    let int = |value: i64| Value::Integer(value.into());
    let mut key = vec![
        (int(1), int(kty.to_i64())),
        (int(-1), int(crv.to_i64())),
        (int(-2), Value::Bytes(vec![0; 32])),
    ];
    if kty == iana::KeyType::EC2 {
        key.push((int(-3), Value::Bytes(vec![0; 32])));
    }
    Ok(key)
}

fn integer(view: &Node<'_>, name: &'static str) -> Result<i64, IssueError> {
    match view.get(name) {
        Some(Node::Number(number)) => number.text().parse().map_err(|_| IssueError::View(name)),
        _ => Err(IssueError::View(name)),
    }
}

/// The IssuerSigned of a view: per name space of `values` (each object-valued member), in order,
/// an item with a running
/// `digestID`, 16 bytes of `random` from SHA-256 of the docType, name space and element, and the
/// value; IssuerAuth with `{1: issuer_alg}` protected and an x5chain unprotected signs (by
/// stand-in) an MSO holding SHA-256 value digests of the tagged items, the device key and the
/// validity.
///
/// # Errors
///
/// The view lacks `type`, `values`, `issuer_alg` or `device_curve`, `issuer_alg` is outside
/// IANA's registry, or a value does not convert.
pub fn issue(view: &Node<'_>) -> Result<Vec<u8>, IssueError> {
    let doctype = view
        .get("type")
        .and_then(Node::as_str)
        .ok_or(IssueError::View("type"))?;
    let values = view
        .get("values")
        .and_then(Node::as_object)
        .ok_or(IssueError::View("values"))?;
    let alg = iana::Algorithm::from_i64(integer(view, "issuer_alg")?)
        .ok_or(IssueError::View("issuer_alg"))?;
    let curve = view
        .get("device_curve")
        .and_then(Node::as_str)
        .ok_or(IssueError::View("device_curve"))?;
    let text = |s: &str| Value::Text(s.to_owned());
    let (mut spaces, mut digests, mut digest_id) = (Vec::new(), Vec::new(), 0u64);
    // The reference model's views hold scalars and arrays beside the name spaces, which no
    // claims path of an mdoc reaches (OpenID4VP §7.2); the issuer signs the object-valued ones.
    let namespaces = values
        .members()
        .iter()
        .filter_map(|namespace| Some((namespace, namespace.value.as_object()?)));
    for (namespace, elements) in namespaces {
        let (mut items, mut space_digests) = (Vec::new(), Vec::new());
        for element in elements.members() {
            let random = Sha256::digest(format!(
                "random:{doctype}:{}:{}",
                namespace.name, element.name
            ));
            let item = Value::Map(vec![
                (text("digestID"), Value::Integer(digest_id.into())),
                (
                    text("random"),
                    Value::Bytes(random.iter().take(16).copied().collect()),
                ),
                (text("elementIdentifier"), text(&element.name)),
                (text("elementValue"), cbor::of_json(&element.value)?),
            ]);
            let tagged = embedded(cbor::encode(&item)?);
            space_digests.push((
                Value::Integer(digest_id.into()),
                Value::Bytes(Sha256::digest(cbor::encode(&tagged)?).to_vec()),
            ));
            items.push(tagged);
            digest_id += 1;
        }
        spaces.push((text(&namespace.name), Value::Array(items)));
        digests.push((text(&namespace.name), Value::Map(space_digests)));
    }
    let date = |at: &str| Value::Tag(0, Box::new(text(at)));
    let mso = Value::Map(vec![
        (text("version"), text("1.0")),
        (text("digestAlgorithm"), text("SHA-256")),
        (text("valueDigests"), Value::Map(digests)),
        (
            text("deviceKeyInfo"),
            Value::Map(vec![(text("deviceKey"), Value::Map(device_key(curve)?))]),
        ),
        (text("docType"), text(doctype)),
        (
            text("validityInfo"),
            Value::Map(vec![
                (text("signed"), date("2026-01-01T00:00:00Z")),
                (text("validFrom"), date("2026-01-01T00:00:00Z")),
                (text("validUntil"), date("2027-01-01T00:00:00Z")),
            ]),
        ),
    ]);
    let payload = cbor::encode(&embedded(cbor::encode(&mso)?))?;
    let unprotected = HeaderBuilder::new()
        .value(
            iana::HeaderParameter::X5Chain.to_i64(),
            Value::Bytes(b"issuer-certificate".to_vec()),
        )
        .build();
    let issuer_auth = CoseSign1Builder::new()
        .protected(HeaderBuilder::new().algorithm(alg).build())
        .unprotected(unprotected)
        .payload(payload)
        .create_signature(b"", |data| {
            format!("issuer-sig:{}", digest_prefix(data)).into_bytes()
        })
        .build()
        .to_cbor_value()
        .map_err(IssueError::Cose)?;
    Ok(cbor::encode(&Value::Map(vec![
        (text("nameSpaces"), Value::Map(spaces)),
        (text("issuerAuth"), issuer_auth),
    ]))?)
}
