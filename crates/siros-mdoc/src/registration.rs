//! The registration: a stored mdoc read (9.1.2) and held as the `mso_mdoc` document, its view built
//! from its items and MSO, with `validityInfo`. The wallet checks `issuerAuth`'s signature and
//! chain before it registers (siros-trust).

use std::borrow::Cow;

use siros_explain::Explain;
use siros_openid4vp::cbor::{self, CborError};
use siros_openid4vp::json::{Node, Object};
use siros_openid4vp::known_object;
use siros_openid4vp::wallet::{DocumentBytes, ViewBytes};

use crate::stored::{Curve, MdocError, StoredMdoc};

/// The issuer's name from `x5chain`: any text its certificate states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuerName<'a>(&'a str);

impl<'a> IssuerName<'a> {
    /// The name `text`.
    #[must_use]
    pub const fn new(text: &'a str) -> Self {
        Self(text)
    }

    /// The name.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

/// What the wallet resolved beside the stored mdoc.
#[derive(Debug, Clone, Default)]
pub struct Resolved<'a> {
    /// The credential's display metadata (OpenID4VCI B.2); `None` when its issuer publishes none.
    pub metadata: Option<Object<'a>>,
    /// The issuer's name from `x5chain`.
    pub issuer: Option<IssuerName<'a>>,
    /// The curve of `x5chain`'s Document Signer key.
    pub issuer_curve: Option<Curve>,
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
    /// "device_alg"?, "device_curve", "key_authorizations", "validity"}`.
    #[must_use]
    pub fn view(&self) -> ViewBytes<'_> {
        ViewBytes::new(&self.view)
    }

    /// The document, under [`crate::issuer_signed::DOCUMENT`].
    #[must_use]
    pub fn document(&self) -> DocumentBytes<'_> {
        DocumentBytes::new(&self.document)
    }
}

/// `{name space: {element: value}}`, values by RFC 8949 §6.1.
fn values(mdoc: &StoredMdoc) -> Result<Object<'static>, CborError> {
    mdoc.distinct_name_spaces().try_object(|space| {
        space
            .distinct_items()
            .try_object(|item| cbor::to_json(item.value()))
            .map(Node::Object)
    })
}

/// `{"namespaces", "elements"}` (ISO/IEC 18013-5 §9.1.2.4).
fn key_authorizations(mdoc: &StoredMdoc) -> Node<'static> {
    let authorizations = mdoc.mso().key_authorizations();
    let names = |names: Vec<&str>| Node::Array(names.into_iter().map(text).collect());
    let elements = authorizations.data_elements().object(|elements| {
        names(
            elements
                .identifiers()
                .iter()
                .map(|id| id.as_str())
                .collect(),
        )
    });
    let namespaces = names(
        authorizations
            .name_spaces()
            .iter()
            .map(|space| space.as_str())
            .collect(),
    );
    Node::Object(known_object! {
        "namespaces" => Some(namespaces),
        "elements" => Some(Node::Object(elements)),
    })
}

fn view(mdoc: &StoredMdoc, resolved: &Resolved<'_>) -> Result<Node<'static>, RegistrationError> {
    let metadata = resolved
        .metadata
        .as_ref()
        .map_or_else(Object::default, |metadata| metadata.clone().into_owned());
    let mso = mdoc.mso();
    let device = mso.device_key();
    let validity = mso.validity();
    let seconds = |at: u64| Some(Node::integer(i128::from(at)));
    let cose = |alg: i64| Node::integer(i128::from(alg));
    Ok(Node::Object(known_object! {
        "type" => Some(text(mdoc.doc_type().as_str())),
        "metadata" => Some(Node::Object(metadata)),
        "values" => Some(Node::Object(values(mdoc)?)),
        "issuer" => resolved.issuer.map(|issuer| text(issuer.as_str())),
        "issuer_alg" => Some(cose(mdoc.issuer_auth().algorithm().value())),
        "issuer_curve" => resolved.issuer_curve.map(|curve| text(curve.name())),
        "device_alg" => device.algorithm().map(|alg| cose(alg.value())),
        "device_curve" => Some(text(device.curve().name())),
        "key_authorizations" => Some(key_authorizations(mdoc)),
        "validity" => Some(Node::Object(known_object! {
            "not_before" => seconds(validity.valid_from().0),
            "not_after" => seconds(validity.valid_until().0),
        })),
    }))
}
