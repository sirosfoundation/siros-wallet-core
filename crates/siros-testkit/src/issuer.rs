//! The issuer stand-in: the IssuerSigned (ISO/IEC 18013-5 §8.3.2.1.2.2) of a credential view
//! the reference model wrote, which a registration holds as its `mso_mdoc` document. One
//! IssuerSignedItem per value (RFC 8949 §6.2 of the JSON), and an IssuerAuth whose
//! MobileSecurityObject digests each item.

use std::borrow::Cow;

use sha2::{Digest, Sha256};
use siros_explain::Explain;
use siros_openid4vp::cbor::cose::coset::iana::{self, EnumI64};
use siros_openid4vp::cbor::cose::coset::{self, AsCborValue, CoseSign1Builder, HeaderBuilder};
use siros_openid4vp::cbor::{self, CborError, Value};
use siros_openid4vp::json::Node;

use crate::host::digest_prefix;

/// The document key under which a registration holds its IssuerSigned.
pub const DOCUMENT: &str = "mso_mdoc";

/// The name space of the digest a credential showing no element withholds.
const WITHHELD: &str = "org.example.withheld";

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

/// RFC 9053 §7.1's key type and curve of a curve name the view states, as a COSE_Key, with the
/// algorithm the view states.
fn device_key(curve: &str, alg: Option<i64>) -> Result<Vec<(Value, Value)>, IssueError> {
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
    if let Some(alg) = alg {
        key.push((int(3), int(alg)));
    }
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

/// A view states no `validity`: the validity its credential takes.
const NOT_BEFORE: i64 = 1_767_225_600;
const NOT_AFTER: i64 = 1_798_761_600;

/// The view's validity in seconds: `validity`, else [`NOT_BEFORE`] and [`NOT_AFTER`].
fn validity_of(view: &Node<'_>) -> Result<(i64, i64), IssueError> {
    let Some(validity) = view.get("validity") else {
        return Ok((NOT_BEFORE, NOT_AFTER));
    };
    Ok((
        integer(validity, "not_before")?,
        integer(validity, "not_after")?,
    ))
}

/// A `tdate` of whole seconds since the epoch (RFC 3339; civil-from-days after H. Hinnant, "chrono-
/// Compatible Low-Level Date Algorithms").
fn tdate(seconds: i64) -> String {
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// `KeyAuthorizations` of the view's `key_authorizations`, empty members left out
/// (ISO/IEC 18013-5 §9.1.2.4); `None` with neither.
fn key_authorizations(view: &Node<'_>) -> Result<Option<Value>, IssueError> {
    let Some(stated) = view.get("key_authorizations") else {
        return Ok(None);
    };
    let bad = || IssueError::View("key_authorizations");
    let texts = |node: &Node<'_>| -> Result<Value, IssueError> {
        let items = node
            .as_array()
            .ok_or_else(bad)?
            .iter()
            .map(|item| {
                item.as_str()
                    .map(|text| Value::Text(text.to_owned()))
                    .ok_or_else(bad)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Value::Array(items))
    };
    let mut members = Vec::new();
    if let Some(namespaces) = stated
        .get("namespaces")
        .filter(|listed| listed.as_array().is_none_or(|listed| !listed.is_empty()))
    {
        members.push((Value::Text("nameSpaces".to_owned()), texts(namespaces)?));
    }
    if let Some(elements) = stated
        .get("elements")
        .and_then(Node::as_object)
        .filter(|elements| !elements.members().is_empty())
    {
        let entries = elements
            .members()
            .iter()
            .map(|member| Ok((Value::Text(member.name.to_string()), texts(&member.value)?)))
            .collect::<Result<Vec<_>, IssueError>>()?;
        members.push((Value::Text("dataElements".to_owned()), Value::Map(entries)));
    }
    Ok((!members.is_empty()).then_some(Value::Map(members)))
}

/// The IssuerSigned of a view: per name space of `values` (each object-valued member), in order,
/// an item with a running
/// `digestID`, 16 bytes of `random` from SHA-256 of the docType, name space and element, and the
/// value; IssuerAuth with `{1: issuer_alg}` protected and an x5chain unprotected signs (by
/// stand-in) an MSO holding SHA-256 value digests of the tagged items, the device key with
/// `device_alg` and `key_authorizations`, and `validity` or a year from 2026-01-01.
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
    let namespaces = values.members().iter().filter_map(|namespace| {
        namespace
            .value
            .as_object()
            .filter(|elements| !elements.members().is_empty())
            .map(|elements| (namespace, elements))
    });
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
    // `valueDigests` is non-empty (§9.1.2.4): a credential showing no element holds one it withheld.
    if digests.is_empty() {
        digests.push((
            text(WITHHELD),
            Value::Map(vec![(Value::Integer(0.into()), Value::Bytes(vec![0; 32]))]),
        ));
    }
    let date = |at: i64| Value::Tag(0, Box::new(text(&tdate(at))));
    let (not_before, not_after) = validity_of(view)?;
    let device_alg = match view.get("device_alg") {
        None => None,
        Some(_) => Some(integer(view, "device_alg")?),
    };
    let mut device_info = vec![(
        text("deviceKey"),
        Value::Map(device_key(curve, device_alg)?),
    )];
    if let Some(authorizations) = key_authorizations(view)? {
        device_info.push((text("keyAuthorizations"), authorizations));
    }
    let mso = Value::Map(vec![
        (text("version"), text("1.0")),
        (text("digestAlgorithm"), text("SHA-256")),
        (text("valueDigests"), Value::Map(digests)),
        (text("deviceKeyInfo"), Value::Map(device_info)),
        (text("docType"), text(doctype)),
        (
            text("validityInfo"),
            Value::Map(vec![
                (text("signed"), date(not_before)),
                (text("validFrom"), date(not_before)),
                (text("validUntil"), date(not_after)),
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
    let mut issued = Vec::with_capacity(2);
    if !spaces.is_empty() {
        issued.push((text("nameSpaces"), Value::Map(spaces)));
    }
    issued.push((text("issuerAuth"), issuer_auth));
    Ok(cbor::encode(&Value::Map(issued))?)
}

/// The view a registration of [`issue`]'s IssuerSigned makes: the written view's `type`, `metadata`,
/// non-null `issuer`, signer and device key, `values` of its non-empty object-valued members,
/// `key_authorizations`, empty members and all, and the validity the credential takes.
///
/// # Errors
///
/// As [`issue`].
pub fn registered_view(view: &Node<'_>) -> Result<Node<'static>, IssueError> {
    let values = view
        .get("values")
        .and_then(Node::as_object)
        .ok_or(IssueError::View("values"))?;
    let shown = values
        .members()
        .iter()
        .filter(|member| {
            member
                .value
                .as_object()
                .is_some_and(|elements| !elements.members().is_empty())
        })
        .map(|member| {
            (
                Cow::Owned(member.name.to_string()),
                member.value.clone().into_owned(),
            )
        });
    let mut members: Vec<(Cow<'static, str>, Node<'static>)> =
        vec![(Cow::Borrowed("values"), Node::object(shown)?)];
    for name in [
        "type",
        "metadata",
        "issuer",
        "issuer_alg",
        "issuer_curve",
        "device_alg",
        "device_curve",
    ] {
        match view.get(name) {
            None | Some(Node::Null) => {}
            Some(value) => members.push((Cow::Borrowed(name), value.clone().into_owned())),
        }
    }
    let stated = view.get("key_authorizations");
    let listed = |name: &str| {
        stated
            .and_then(|stated| stated.get(name))
            .map(|value| value.clone().into_owned())
    };
    members.push((
        Cow::Borrowed("key_authorizations"),
        Node::object([
            (
                Cow::Borrowed("namespaces"),
                listed("namespaces").unwrap_or(Node::Array(Vec::new())),
            ),
            (
                Cow::Borrowed("elements"),
                listed("elements").map_or_else(|| Node::object([]), Ok)?,
            ),
        ])?,
    ));
    let (not_before, not_after) = validity_of(view)?;
    members.push((
        Cow::Borrowed("validity"),
        Node::object([
            (
                Cow::Borrowed("not_before"),
                Node::integer(i128::from(not_before)),
            ),
            (
                Cow::Borrowed("not_after"),
                Node::integer(i128::from(not_after)),
            ),
        ])?,
    ));
    Ok(Node::object(members)?)
}
