//! The IssuerSigned the wallet stored at issuance, the credential's `mso_mdoc` document
//! (ISO/IEC 18013-5 §8.3.2.1.2.2), and the part of it a presentation discloses.

use siros_explain::Explain;
use siros_openid4vp::cbor::cose::coset::{self, AsCborValue, CoseSign1};
use siros_openid4vp::cbor::cose::{CoseShape, read_sign1};
use siros_openid4vp::cbor::{self, CborError, Value, embedded};
use siros_openid4vp::json::Node;

use crate::stored::{DocType, ElementIdentifier, NameSpace};

/// The document key under which a registration holds its IssuerSigned.
pub const DOCUMENT: &str = "mso_mdoc";

/// One IssuerSignedItem as issued: the embedded bytes the MSO's digest covers, and what they say.
#[derive(Debug, Clone, PartialEq)]
struct IssuedItem {
    bytes: Vec<u8>,
    identifier: ElementIdentifier,
    value: Value,
}

/// A name space's items as issued.
#[derive(Debug, Clone, PartialEq)]
struct IssuedNameSpace {
    name: NameSpace,
    items: Vec<IssuedItem>,
}

/// IssuerSigned: per name space the items as issued, and IssuerAuth, a COSE_Sign1 whose protected
/// header and payload stay the issuer's bytes, with the docType of the MSO it carries.
#[derive(Debug, Clone, PartialEq)]
pub struct IssuerSigned {
    namespaces: Vec<IssuedNameSpace>,
    issuer_auth: CoseSign1,
    doctype: DocType,
}

/// An issuer-signed data element a presentation discloses, with the value the view shows.
#[derive(Debug, Clone)]
pub struct Disclosed<'a> {
    /// The name space.
    pub namespace: NameSpace,
    /// The data element identifier.
    pub element: ElementIdentifier,
    /// The value the view shows, which the End-User consented to.
    pub shown: &'a Node<'a>,
}

/// Why a stored IssuerSigned cannot be presented.
#[derive(Debug, thiserror::Error, Explain)]
pub enum IssuedError {
    /// No CBOR the wallet reads.
    #[error("no CBOR the wallet reads")]
    #[explain(id = "issued.cbor")]
    Cbor(#[from] CborError),
    /// Another shape than ISO/IEC 18013-5's CDDL, or an unknown member.
    #[error("{0}")]
    #[explain(id = "issued.shape")]
    Shape(#[explain(skip)] String),
    /// IssuerAuth is no COSE_Sign1 the wallet reads.
    #[error("IssuerAuth")]
    #[explain(id = "issued.issuer_auth")]
    IssuerAuth(#[from] CoseShape),
    /// coset cannot write IssuerAuth back.
    #[error("IssuerAuth does not encode")]
    #[explain(id = "issued.encode")]
    Encode(#[source] coset::CoseError),
    /// One element identifier twice in a name space.
    #[error("{namespace}: {element} issued twice")]
    #[explain(id = "issued.twice")]
    Twice {
        /// The name space.
        namespace: NameSpace,
        /// The element identifier.
        element: ElementIdentifier,
    },
    /// The view discloses an element the issuer did not sign.
    #[error("{namespace}: {element} was not issued")]
    #[explain(id = "issued.missing")]
    Missing {
        /// The name space.
        namespace: NameSpace,
        /// The element identifier.
        element: ElementIdentifier,
    },
    /// The issued value differs from the view's: the End-User consented to another value.
    #[error("{namespace}: {element}'s issued value is not the view's")]
    #[explain(id = "issued.differs")]
    Differs {
        /// The name space.
        namespace: NameSpace,
        /// The element identifier.
        element: ElementIdentifier,
    },
}

fn shape(what: impl Into<String>) -> IssuedError {
    IssuedError::Shape(what.into())
}

fn text(value: Value, what: &str) -> Result<String, IssuedError> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(shape(what)),
    }
}

/// The embedded item's bytes and its decoding: `#6.24(bstr .cbor item)`.
fn unembedded(value: Value, what: &str) -> Result<(Vec<u8>, Value), IssuedError> {
    let Value::Tag(24, inner) = value else {
        return Err(shape(format!("{what} that is no tag 24")));
    };
    let Value::Bytes(bytes) = *inner else {
        return Err(shape(format!("{what} that holds no byte string")));
    };
    let item = cbor::decode(&bytes)?;
    Ok((bytes, item))
}

impl IssuedItem {
    /// `#6.24(bstr .cbor IssuerSignedItem)`: `digestID`, `random`, `elementIdentifier` and
    /// `elementValue`, each once, nothing else.
    fn read(tagged: Value) -> Result<Self, IssuedError> {
        let (bytes, item) = unembedded(tagged, "an IssuerSignedItemBytes")?;
        let Value::Map(members) = item else {
            return Err(shape("an IssuerSignedItem that is no map"));
        };
        let (mut digest_id, mut random, mut identifier, mut value) = (false, false, None, None);
        for (name, item) in members {
            match (
                text(name, "an IssuerSignedItem key that is no text")?.as_str(),
                item,
            ) {
                ("digestID", Value::Integer(_)) => digest_id = true,
                ("random", Value::Bytes(_)) => random = true,
                ("elementIdentifier", Value::Text(element)) => identifier = Some(element),
                ("elementValue", element_value) => value = Some(element_value),
                (other, _) => {
                    return Err(shape(format!(
                        "an IssuerSignedItem member {other}, unknown or of another type"
                    )));
                }
            }
        }
        match (digest_id, random, identifier, value) {
            (true, true, Some(identifier), Some(value)) => Ok(Self {
                bytes,
                identifier: ElementIdentifier::new(&identifier),
                value,
            }),
            _ => Err(shape("an IssuerSignedItem without its four members")),
        }
    }
}

impl IssuedNameSpace {
    /// A name space's items, each element identifier once.
    fn read(name: Value, items: Value) -> Result<Self, IssuedError> {
        let name = NameSpace::new(&text(name, "a name space that is no text")?);
        let Value::Array(items) = items else {
            return Err(shape("a name space's items that are no array"));
        };
        let items = items
            .into_iter()
            .map(IssuedItem::read)
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(twice) = items.iter().enumerate().find_map(|(k, item)| {
            items
                .get(..k)?
                .iter()
                .find(|before| before.identifier == item.identifier)
        }) {
            return Err(IssuedError::Twice {
                element: twice.identifier.clone(),
                namespace: name,
            });
        }
        Ok(Self { name, items })
    }
}

/// The MSO's `docType`: IssuerAuth's payload is an embedded item holding the MobileSecurityObject
/// map.
fn mso_doctype(issuer_auth: &CoseSign1) -> Result<DocType, IssuedError> {
    let payload = issuer_auth
        .payload
        .as_deref()
        .ok_or_else(|| shape("IssuerAuth without its MSO"))?;
    let (_, mso) = unembedded(cbor::decode(payload)?, "an MSO")?;
    let Value::Map(members) = mso else {
        return Err(shape("an MSO that is no map"));
    };
    members
        .into_iter()
        .find_map(|(key, value)| match (key, value) {
            (Value::Text(key), Value::Text(doctype)) if key == "docType" => {
                Some(DocType::new(&doctype))
            }
            _ => None,
        })
        .ok_or_else(|| shape("an MSO without a docType text"))
}

impl IssuerSigned {
    /// The stored IssuerSigned: `nameSpaces`, when present, and `issuerAuth`, nothing else;
    /// IssuerAuth's payload is the embedded MSO, which holds a `docType` text.
    pub fn read(document: &[u8]) -> Result<Self, IssuedError> {
        let Value::Map(members) = cbor::decode(document)? else {
            return Err(shape("an IssuerSigned that is no map"));
        };
        let (mut namespaces, mut issuer_auth) = (Vec::new(), None);
        for (name, item) in members {
            match (text(name, "a key that is no text")?.as_str(), item) {
                ("nameSpaces", Value::Map(spaces)) => {
                    namespaces = spaces
                        .into_iter()
                        .map(|(name, items)| IssuedNameSpace::read(name, items))
                        .collect::<Result<_, _>>()?;
                }
                ("issuerAuth", value) => issuer_auth = Some(read_sign1(value)?),
                (other, _) => {
                    return Err(shape(format!(
                        "an IssuerSigned member {other}, unknown or of another type"
                    )));
                }
            }
        }
        let issuer_auth = issuer_auth.ok_or_else(|| shape("an IssuerSigned without issuerAuth"))?;
        let doctype = mso_doctype(&issuer_auth)?;
        Ok(Self {
            namespaces,
            issuer_auth,
            doctype,
        })
    }

    /// The MSO's `docType` (ISO/IEC 18013-5 §9.1.2.4).
    #[must_use]
    pub fn doctype(&self) -> &DocType {
        &self.doctype
    }

    /// The IssuerSigned a presentation holds: the disclosed elements' items as issued, by name
    /// space in the order each first comes, `nameSpaces` left out when none is disclosed; and
    /// IssuerAuth as stored. Each issued value, read by RFC 8949 §6.1, equals the view's.
    pub fn disclose(&self, disclosed: &[Disclosed<'_>]) -> Result<Value, IssuedError> {
        let mut spaces: Vec<(Value, Value)> = Vec::new();
        for shown in disclosed {
            let named = |error: fn(NameSpace, ElementIdentifier) -> IssuedError| {
                error(shown.namespace.clone(), shown.element.clone())
            };
            let item = self
                .namespaces
                .iter()
                .find(|space| space.name == shown.namespace)
                .and_then(|space| {
                    space
                        .items
                        .iter()
                        .find(|item| item.identifier == shown.element)
                })
                .ok_or_else(|| {
                    named(|namespace, element| IssuedError::Missing { namespace, element })
                })?;
            if cbor::to_json(&item.value)? != *shown.shown {
                return Err(named(|namespace, element| IssuedError::Differs {
                    namespace,
                    element,
                }));
            }
            let key = Value::Text(shown.namespace.as_str().to_owned());
            let tagged = embedded(item.bytes.clone());
            match spaces.iter_mut().find(|(name, _)| *name == key) {
                Some((_, Value::Array(items))) => items.push(tagged),
                _ => spaces.push((key, Value::Array(vec![tagged]))),
            }
        }
        let issuer_auth = self
            .issuer_auth
            .clone()
            .to_cbor_value()
            .map_err(IssuedError::Encode)?;
        let mut members = Vec::new();
        if !spaces.is_empty() {
            members.push((Value::Text("nameSpaces".to_owned()), Value::Map(spaces)));
        }
        members.push((Value::Text("issuerAuth".to_owned()), issuer_auth));
        Ok(Value::Map(members))
    }
}
