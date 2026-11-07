//! The registration: a stored mdoc read (9.1.2) and held as the `mso_mdoc` document, its view built
//! from its items and MSO, with `validityInfo`. The wallet checks `issuerAuth`'s signature and
//! chain before it registers (siros-trust).

use std::borrow::Cow;

use siros_explain::Explain;
use siros_openid4vp::cbor::{self, CborError, Value};
use siros_openid4vp::claims::kit::{
    IssuedMetadata, IssuedShape, MergeError, full_date, merge_metadata, tdate,
};
use siros_openid4vp::json::{Node, Object};
use siros_openid4vp::known_object;
use siros_openid4vp::wallet::{DocumentBytes, ViewBytes};

use crate::stored::{Curve, ElementIdentifier, MdocError, NameSpace, StoredMdoc};

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
    /// What OpenID4VCI states of the credential's display, the format stating none of its own.
    pub issued: IssuedMetadata<'a>,
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
    /// "issuer"?, "issuer_alg", "issuer_curve"?, "device_alg"?, "device_curve",
    /// "key_authorizations", "validity"}`.
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

    fn date(&mut self, path: &[Node<'static>], written: &str) {
        self.dates.push(Node::Object(known_object! {
            "path" => Some(Node::Array(path.to_vec())),
            "date" => Some(text(written)),
        }));
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
                self.byte_strings.push(Node::Object(known_object! {
                    "path" => Some(Node::Array(path.clone())),
                    "length" => Some(Node::natural(bytes.len())),
                }));
            }
            Value::Tag(2 | 3, _) => {}
            Value::Tag(1004, inner) => match inner.as_ref() {
                Value::Text(written) if full_date(written).is_some() => {
                    self.date(path, written);
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
                    self.date(path, written);
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
    let metadata = merge_metadata::<IssuedAsWritten>(None, &resolved.issued)?;
    let mso = mdoc.mso();
    let device = mso.device_key();
    let validity = mso.validity();
    let seconds = |at: u64| Some(Node::integer(i128::from(at)));
    let cose = |alg: i64| Node::integer(i128::from(alg));
    let values = values(mdoc)?;
    let typed = Typed::of(mdoc)?;
    Ok(Node::Object(known_object! {
        "type" => Some(text(mdoc.doc_type().as_str())),
        "metadata" => Some(Node::Object(metadata)),
        "values" => Some(Node::Object(values)),
        "byte_strings" => (!typed.byte_strings.is_empty()).then_some(Node::Array(typed.byte_strings)),
        "dates" => (!typed.dates.is_empty()).then_some(Node::Array(typed.dates)),
        "issuer_display" => resolved.issued.issuer_display_member()?,
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
