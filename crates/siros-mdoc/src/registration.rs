//! The registration: a stored mdoc read (9.1.2) and held as the `mso_mdoc` document, its view built
//! from its items and MSO, with `validityInfo`. The wallet checks `issuerAuth`'s signature and
//! chain before it registers (siros-trust).

use std::borrow::Cow;

use siros_explain::Explain;
use siros_openid4vp::cbor::{self, CborError};
use siros_openid4vp::json::{JsonError, Node};

use crate::stored::{MdocError, StoredMdoc};

/// What the wallet resolved beside the stored mdoc.
#[derive(Debug, Clone, Default)]
pub struct Resolved<'a> {
    /// The credential's display metadata (OpenID4VCI B.2); `None` when its issuer publishes none.
    pub metadata: Option<Node<'a>>,
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
    /// The metadata is no object.
    #[error("the display metadata is no object")]
    Metadata,
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

    /// The view: `{"type", "metadata", "values", "issuer"?, "issuer_alg", "issuer_curve"?,
    /// "device_alg", "device_curve", "key_authorizations", "validity"}`.
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
    let metadata = match &resolved.metadata {
        None => Node::object([])?,
        Some(metadata) if metadata.as_object().is_some() => metadata.clone().into_owned(),
        Some(_) => return Err(RegistrationError::Metadata),
    };
    let mso = mdoc.mso();
    let device = mso.device_key();
    let validity = mso.validity();
    let seconds = |at: u64| Node::integer(i128::from(at));
    let mut members: Members = vec![
        (Cow::Borrowed("type"), text(mdoc.doc_type().as_str())),
        (Cow::Borrowed("metadata"), metadata),
        (Cow::Borrowed("values"), values(mdoc)?),
    ];
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
