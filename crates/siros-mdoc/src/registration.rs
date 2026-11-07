//! The registration: a stored mdoc read (9.1.2) and held as the `mso_mdoc` document, its view built
//! from its items and MSO, with `validityInfo`. The wallet checks `issuerAuth`'s signature and
//! chain before it registers (siros-trust).

use std::borrow::Cow;

use siros_explain::Explain;
use siros_openid4vp::cbor::{self, CborError, Value};
use siros_openid4vp::claims::kit::{
    IssuedMetadata, IssuedShape, MergeError, full_date, merge_metadata, tdate,
};
use siros_openid4vp::json::{JsonError, Node};

use crate::stored::{ElementIdentifier, MdocError, NameSpace, StoredMdoc};

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
    /// A value under tag 1004 is no `full-date` (RFC 8943, ISO/IEC 18013-5 §7.2.1).
    #[error("{namespace}: {element} holds a value under tag 1004 that is no `full-date`")]
    FullDate {
        /// The name space.
        namespace: NameSpace,
        /// The element identifier.
        element: ElementIdentifier,
    },
    /// A value under tag 0 is no `tdate` of the form `YYYY-MM-DDThh:mm:ssZ` (ISO/IEC 18013-5
    /// §9.1.2.4).
    #[error("{namespace}: {element} holds a value under tag 0 that is no `tdate`")]
    Tdate {
        /// The name space.
        namespace: NameSpace,
        /// The element identifier.
        element: ElementIdentifier,
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
            view: view.json_compact().to_string().into_bytes(),
            document: mdoc.issuer_signed().to_vec(),
        })
    }

    /// The view: `{"type", "metadata", "values", "byte_strings"?, "dates"?, "issuer_display"?,
    /// "issuer"?, "issuer_alg", "issuer_curve"?, "device_alg", "device_curve",
    /// "key_authorizations", "validity"}`.
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

/// A located entry of the view: `{"path", name: value}`.
fn located(
    path: &[Node<'static>],
    name: &'static str,
    value: Node<'static>,
) -> Result<Node<'static>, JsonError> {
    Node::object([
        (Cow::Borrowed("path"), Node::Array(path.to_vec())),
        (Cow::Borrowed(name), value),
    ])
}

/// What the items' values state that RFC 8949 §6.1 leaves out of the text in `values`.
#[derive(Default)]
struct Typed {
    /// Each byte string as `{"path", "length"}`. A bignum (tags 2 and 3) is a number.
    byte_strings: Vec<Node<'static>>,
    /// Each `full-date` and `tdate` as `{"path", "date"}` (ISO/IEC 18013-5 §7.2.1).
    dates: Vec<Node<'static>>,
}

impl Typed {
    /// What the items of `mdoc` state.
    fn of(mdoc: &StoredMdoc) -> Result<Self, RegistrationError> {
        let mut typed = Self::default();
        for space in mdoc.name_spaces() {
            for item in space.items() {
                let mut path = vec![
                    text(&space.name().to_string()),
                    text(&item.identifier().to_string()),
                ];
                typed.under(item.value(), &mut path, (space.name(), item.identifier()))?;
            }
        }
        Ok(typed)
    }

    /// Reads `value`, at `path` under the element `item`.
    fn under(
        &mut self,
        value: &Value,
        path: &mut Vec<Node<'static>>,
        item: (&NameSpace, &ElementIdentifier),
    ) -> Result<(), RegistrationError> {
        match value {
            Value::Bytes(bytes) => {
                self.byte_strings
                    .push(located(path, "length", Node::natural(bytes.len()))?);
            }
            Value::Tag(2 | 3, _) => {}
            Value::Tag(1004, inner) => match inner.as_ref() {
                Value::Text(written) if full_date(written).is_some() => {
                    self.dates.push(located(path, "date", text(written))?);
                }
                _ => {
                    return Err(RegistrationError::FullDate {
                        namespace: item.0.clone(),
                        element: item.1.clone(),
                    });
                }
            },
            Value::Tag(0, inner) => match inner.as_ref() {
                Value::Text(written) if tdate(written).is_some() => {
                    self.dates.push(located(path, "date", text(written))?);
                }
                _ => {
                    return Err(RegistrationError::Tdate {
                        namespace: item.0.clone(),
                        element: item.1.clone(),
                    });
                }
            },
            Value::Tag(_, inner) => self.under(inner, path, item)?,
            Value::Array(items) => {
                for (at, inner) in items.iter().enumerate() {
                    path.push(Node::natural(at));
                    self.under(inner, path, item)?;
                    drop(path.pop());
                }
            }
            Value::Map(pairs) => {
                for (key, inner) in pairs {
                    if let Value::Text(name) = key {
                        path.push(text(name));
                        self.under(inner, path, item)?;
                        drop(path.pop());
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
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
    let typed = Typed::of(mdoc)?;
    if !typed.byte_strings.is_empty() {
        members.push((
            Cow::Borrowed("byte_strings"),
            Node::Array(typed.byte_strings),
        ));
    }
    if !typed.dates.is_empty() {
        members.push((Cow::Borrowed("dates"), Node::Array(typed.dates)));
    }
    members.extend(resolved.issued.issuer_display_member()?);
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
