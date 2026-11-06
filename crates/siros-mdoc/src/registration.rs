//! The registration: a stored mdoc read (9.1.2) and held as the `mso_mdoc` document, its view built
//! from its items and MSO, with `validityInfo`. The wallet checks `issuerAuth`'s signature and
//! chain before it registers (siros-trust).

use std::borrow::Cow;

use siros_explain::Explain;
use siros_openid4vp::cbor::{self, CborError, Value};
use siros_openid4vp::claims::kit::{IssuedMetadata, IssuedShape, MergeError, merge_metadata};
use siros_openid4vp::json::{JsonError, Node};

use crate::stored::{MdocError, StoredMdoc};

/// What the wallet resolved beside the stored mdoc.
#[derive(Debug, Clone, Default)]
pub struct Resolved<'a> {
    /// What OpenID4VCI states of the credential's display, the format stating none of its own.
    pub issued: IssuedMetadata<'a>,
    /// The issuer's name from `x5chain`.
    pub issuer: Option<&'a str>,
    /// The curve of `x5chain`'s Document Signer key.
    pub issuer_curve: Option<&'a str>,
}

/// Why a stored mdoc makes no view.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "mdoc.registration")]
pub enum RegistrationError {
    /// The text is no stored mdoc.
    #[error("no stored mdoc")]
    Stored(
        #[source]
        #[explain(skip)]
        MdocError,
    ),
    /// An element's value converts to no JSON (RFC 8949 §6.1).
    #[error("an element's value converts to no JSON")]
    Value(
        #[from]
        #[explain(name = "cause")]
        CborError,
    ),
    /// The view repeats a member name.
    #[error(transparent)]
    Json(#[from] JsonError),
    /// The display metadata breaks a rule of the merge.
    #[error("the display metadata: {cause}")]
    Metadata {
        /// The rule.
        #[from]
        cause: MergeError,
    },
}

/// OpenID4VCI's display metadata, as an mdoc's view holds it.
struct IssuedAsWritten;

impl IssuedShape for IssuedAsWritten {
    const LABEL: &'static str = crate::LABEL;
}

/// A stored mdoc as the registration holds it: the view, and the IssuerSigned phase 2 presents from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    view: Vec<u8>,
    document: Vec<u8>,
}

fn text(value: &str) -> Node<'static> {
    Node::String(Cow::Owned(value.to_owned()))
}

type Members = Vec<(Cow<'static, str>, Node<'static>)>;

impl Registered {
    /// The registration of the base64url mdoc `stored`.
    ///
    /// # Errors
    ///
    /// [`RegistrationError`]: the text is no stored mdoc, or its items make no view.
    pub fn of(stored: &str, resolved: &Resolved<'_>) -> Result<Self, RegistrationError> {
        let mdoc = StoredMdoc::parse(stored).map_err(RegistrationError::Stored)?;
        let view = view(&mdoc, resolved)?;
        Ok(Self {
            view: view.python_compact().to_string().into_bytes(),
            document: mdoc.issuer_signed().to_vec(),
        })
    }

    /// The view: `{"type", "metadata", "values", "byte_strings"?, "issuer"?, "issuer_alg",
    /// "issuer_curve"?, "device_alg", "device_curve", "key_authorizations", "validity"}`.
    #[must_use]
    pub fn view(&self) -> &[u8] {
        &self.view
    }

    /// The document, under [`crate::issuer_signed::DOCUMENT`].
    #[must_use]
    pub fn document(&self) -> &[u8] {
        &self.document
    }
}

/// `{name space: {element: value}}`, values by RFC 8949 §6.1.
fn values(mdoc: &StoredMdoc) -> Result<Node<'static>, RegistrationError> {
    let mut spaces: Members = Vec::with_capacity(mdoc.name_spaces().len());
    for space in mdoc.name_spaces() {
        let mut elements: Members = Vec::with_capacity(space.items().len());
        for item in space.items() {
            elements.push((
                Cow::Owned(item.identifier().to_string()),
                cbor::to_json(item.value())?,
            ));
        }
        spaces.push((
            Cow::Owned(space.name().to_string()),
            Node::object(elements)?,
        ));
    }
    Ok(Node::object(spaces)?)
}

/// Each byte string under the items' values, which RFC 8949 §6.1 writes as text in `values`, as
/// `{"path", "length"}`. A bignum (tags 2 and 3) is a number.
fn byte_strings(mdoc: &StoredMdoc) -> Result<Vec<Node<'static>>, JsonError> {
    let mut found = Vec::new();
    for space in mdoc.name_spaces() {
        for item in space.items() {
            let mut path = vec![
                text(&space.name().to_string()),
                text(&item.identifier().to_string()),
            ];
            bytes_under(item.value(), &mut path, &mut found)?;
        }
    }
    Ok(found)
}

fn bytes_under(
    value: &Value,
    path: &mut Vec<Node<'static>>,
    found: &mut Vec<Node<'static>>,
) -> Result<(), JsonError> {
    match value {
        Value::Bytes(bytes) => found.push(Node::object([
            (Cow::Borrowed("path"), Node::Array(path.clone())),
            (Cow::Borrowed("length"), Node::natural(bytes.len())),
        ])?),
        Value::Tag(2 | 3, _) => {}
        Value::Tag(_, inner) => bytes_under(inner, path, found)?,
        Value::Array(items) => {
            for (at, item) in items.iter().enumerate() {
                path.push(Node::natural(at));
                bytes_under(item, path, found)?;
                drop(path.pop());
            }
        }
        Value::Map(pairs) => {
            for (key, item) in pairs {
                if let Value::Text(name) = key {
                    path.push(text(name));
                    bytes_under(item, path, found)?;
                    drop(path.pop());
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// `{"namespaces", "elements"}` (ISO/IEC 18013-5 §9.1.2.4).
fn key_authorizations(mdoc: &StoredMdoc) -> Result<Node<'static>, RegistrationError> {
    let authorizations = mdoc.mso().key_authorizations();
    let elements: Members = authorizations
        .data_elements()
        .iter()
        .map(|(space, identifiers)| {
            (
                Cow::Owned(space.to_string()),
                Node::Array(identifiers.iter().map(|id| text(id.as_str())).collect()),
            )
        })
        .collect();
    let namespaces = authorizations
        .name_spaces()
        .iter()
        .map(|space| text(space.as_str()))
        .collect();
    Ok(Node::object([
        (Cow::Borrowed("namespaces"), Node::Array(namespaces)),
        (Cow::Borrowed("elements"), Node::object(elements)?),
    ])?)
}

fn view(mdoc: &StoredMdoc, resolved: &Resolved<'_>) -> Result<Node<'static>, RegistrationError> {
    let metadata = merge_metadata::<IssuedAsWritten>(None, &resolved.issued)?;
    let mso = mdoc.mso();
    let device = mso.device_key();
    let validity = mso.validity();
    let seconds = |at: u64| Node::integer(i128::from(at));
    let mut members: Members = vec![
        (Cow::Borrowed("type"), text(mdoc.doc_type().as_str())),
        (Cow::Borrowed("metadata"), metadata),
        (Cow::Borrowed("values"), values(mdoc)?),
    ];
    let byte_strings = byte_strings(mdoc)?;
    if !byte_strings.is_empty() {
        members.push((Cow::Borrowed("byte_strings"), Node::Array(byte_strings)));
    }
    if let Some(issuer) = resolved.issuer {
        members.push((Cow::Borrowed("issuer"), text(issuer)));
    }
    members.push((
        Cow::Borrowed("issuer_alg"),
        Node::integer(i128::from(mdoc.issuer_auth().algorithm().value())),
    ));
    if let Some(curve) = resolved.issuer_curve {
        members.push((Cow::Borrowed("issuer_curve"), text(curve)));
    }
    members.push((
        Cow::Borrowed("device_alg"),
        Node::integer(i128::from(device.algorithm().value())),
    ));
    members.push((Cow::Borrowed("device_curve"), text(device.curve())));
    members.push((
        Cow::Borrowed("key_authorizations"),
        key_authorizations(mdoc)?,
    ));
    members.push((
        Cow::Borrowed("validity"),
        Node::object([
            (
                Cow::Borrowed("not_before"),
                seconds(validity.valid_from().0),
            ),
            (
                Cow::Borrowed("not_after"),
                seconds(validity.valid_until().0),
            ),
        ])?,
    ));
    Ok(Node::object(members)?)
}
