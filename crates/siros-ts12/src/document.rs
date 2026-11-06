//! The registration document `ts12`: the credential's own type metadata's `category` and
//! `transaction_data_types`, each `claims_uri` and `ui_labels_uri` replaced by the document fetched
//! (TS12 §4.1, §4.1.1).

use std::borrow::Cow;

use siros_explain::{Explain, Keyed};
use siros_openid4vp::json::{JsonError, Node, Object};
use siros_openid4vp::plugins::JsonText;
use siros_openid4vp::rows::HttpsUrl;
use siros_paso::rulebook::Family;

/// The key of the TS12 document in a credential's registration.
pub const DOCUMENT: &str = "ts12";
/// TS12 §3: the category of an SCA attestation.
pub const SCA_CATEGORY: &str = "urn:eu:europa:ec:eudi:sua:sca";

const PAYMENT: &str = "urn:eudi:sca:payment:1";
const LOGIN_RISK: &str = "urn:eudi:sca:login_risk_transaction:1";

/// A member fetched at registration and the member it replaces.
const FETCHED: [(&str, &str); 2] = [("claims_uri", "claims"), ("ui_labels_uri", "ui_labels")];

/// The built-in types served (CS-12 §7.1 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ts12Type {
    /// `urn:eudi:sca:payment:1` (TS12 §4.3.1).
    Payment,
    /// `urn:eudi:sca:login_risk_transaction:1` (TS12 §4.3.2).
    LoginRisk,
}

impl Ts12Type {
    /// The type a URN names.
    #[must_use]
    pub fn of(kind: &str) -> Option<Self> {
        match kind {
            PAYMENT => Some(Self::Payment),
            LOGIN_RISK => Some(Self::LoginRisk),
            _ => None,
        }
    }

    /// Its URN.
    #[must_use]
    pub const fn urn(self) -> &'static str {
        match self {
            Self::Payment => PAYMENT,
            Self::LoginRisk => LOGIN_RISK,
        }
    }

    /// The family siros-paso renders it with.
    #[must_use]
    pub const fn family(self) -> Family {
        match self {
            Self::Payment => Family::Payment,
            Self::LoginRisk => Family::View,
        }
    }
}

/// Type metadata the registration cannot compose, or a document it cannot read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "ts12.compose")]
pub enum ComposeError {
    /// No JSON object with unique member names at every level.
    #[error(transparent)]
    Json(#[from] JsonError),
    /// `transaction_data_types` absent, or no object of objects.
    #[error("transaction_data_types is absent or no object of objects")]
    Types,
    /// A member and its `_uri` twin both present (TS12 §4.1).
    #[error("{member}: a member and its _uri twin are both present")]
    Both {
        /// The member.
        member: String,
    },
    /// A `_uri` member naming a document the caller did not fetch.
    #[error("{uri} names a document the caller did not fetch")]
    Unfetched {
        /// The URI as written.
        uri: String,
    },
}

/// A credential's registration document.
#[derive(Debug, Clone)]
pub struct Ts12Document<'d> {
    category: Option<&'d str>,
    types: &'d Object<'d>,
}

impl<'d> Ts12Document<'d> {
    /// The document from the credential's own type metadata and the documents fetched, one per
    /// URL. A type that `extends` another contributes its own members alone: TS12 defines no
    /// inheritance for either.
    ///
    /// # Errors
    ///
    /// [`ComposeError`]: `transaction_data_types` breaks its shape, a member stands beside its
    /// `_uri` twin, a fetched document is missing or is no JSON.
    pub fn compose(
        own: &Node<'_>,
        fetched: &Keyed<HttpsUrl, Vec<u8>>,
    ) -> Result<Vec<u8>, ComposeError> {
        let types = own
            .get("transaction_data_types")
            .and_then(Node::as_object)
            .ok_or(ComposeError::Types)?;
        let composed = types
            .members()
            .iter()
            .map(|member| {
                Ok((
                    Cow::Owned(member.name.to_string()),
                    composed_type(&member.value, fetched)?,
                ))
            })
            .collect::<Result<Vec<_>, ComposeError>>()?;
        let mut document: Vec<(Cow<'static, str>, Node<'static>)> = Vec::new();
        if let Some(category) = own.get("category") {
            document.push((Cow::Borrowed("category"), category.clone().into_owned()));
        }
        document.push((
            Cow::Borrowed("transaction_data_types"),
            Node::object(composed)?,
        ));
        Ok(JsonText::from(&Node::object(document)?)
            .as_str()
            .as_bytes()
            .to_vec())
    }

    /// The document a registration holds.
    ///
    /// # Errors
    ///
    /// [`ComposeError::Types`]: `transaction_data_types` breaks its shape.
    pub fn read(node: &'d Node<'d>) -> Result<Self, ComposeError> {
        let types = node
            .get("transaction_data_types")
            .and_then(Node::as_object)
            .filter(|types| {
                types
                    .members()
                    .iter()
                    .all(|member| member.value.as_object().is_some())
            })
            .ok_or(ComposeError::Types)?;
        Ok(Self {
            category: node.get("category").and_then(Node::as_str),
            types,
        })
    }

    /// `category`.
    #[must_use]
    pub const fn category(&self) -> Option<&'d str> {
        self.category
    }

    /// The entry of a type key.
    #[must_use]
    pub fn entry(&self, kind: &str) -> Option<TypeEntry<'d>> {
        let entry = self.types.get(kind)?;
        let schema = entry
            .get("schema")
            .or_else(|| entry.get("schema_uri"))
            .and_then(Node::as_str);
        Some(TypeEntry {
            built_in: Ts12Type::of(kind).filter(|built_in| schema == Some(built_in.urn())),
            schema,
            claims: entry.get("claims"),
            ui_labels: entry.get("ui_labels"),
        })
    }
}

/// The type's members with each fetched member replaced by the document it names.
fn composed_type(
    entry: &Node<'_>,
    fetched: &Keyed<HttpsUrl, Vec<u8>>,
) -> Result<Node<'static>, ComposeError> {
    let object = entry.as_object().ok_or(ComposeError::Types)?;
    let twice =
        |twin: &str, member: &str| object.get(twin).is_some() && object.get(member).is_some();
    if twice("schema_uri", "schema") {
        return Err(ComposeError::Both {
            member: "schema".to_owned(),
        });
    }
    if let Some((_, member)) = FETCHED.iter().find(|(uri, member)| twice(uri, member)) {
        return Err(ComposeError::Both {
            member: (*member).to_owned(),
        });
    }
    let members = object
        .members()
        .iter()
        .map(
            |member| match FETCHED.iter().find(|(uri, _)| *uri == member.name) {
                Some((_, replaced)) => Ok((
                    Cow::Borrowed(*replaced),
                    document_at(&member.value, fetched)?,
                )),
                None => Ok((
                    Cow::Owned(member.name.to_string()),
                    member.value.clone().into_owned(),
                )),
            },
        )
        .collect::<Result<Vec<_>, ComposeError>>()?;
    Ok(Node::object(members)?)
}

/// The document a `_uri` member names, as the caller fetched it.
fn document_at(
    uri: &Node<'_>,
    fetched: &Keyed<HttpsUrl, Vec<u8>>,
) -> Result<Node<'static>, ComposeError> {
    let unfetched = || ComposeError::Unfetched {
        uri: uri
            .as_str()
            .map_or_else(|| uri.python_compact().to_string(), str::to_owned),
    };
    let url = uri
        .as_str()
        .and_then(|text| HttpsUrl::parse(text).ok())
        .ok_or_else(unfetched)?;
    let bytes = fetched.get(&url).ok_or_else(unfetched)?;
    let text = std::str::from_utf8(bytes).map_err(|e| JsonError::Syntax(e.to_string()))?;
    Ok(Node::parse(text)?.into_owned())
}

/// One `transaction_data_types` entry: the built-in type its `schema` or `schema_uri` names, its
/// claims metadata (TS12 §3.3.2) and its UI labels catalogue (TS12 §3.3.3).
#[derive(Debug, Clone, Copy)]
pub struct TypeEntry<'d> {
    built_in: Option<Ts12Type>,
    schema: Option<&'d str>,
    claims: Option<&'d Node<'d>>,
    ui_labels: Option<&'d Node<'d>>,
}

impl<'d> TypeEntry<'d> {
    /// The entry with the built-in type its key and schema both name; `None` for any other schema.
    #[must_use]
    pub const fn built_in(&self) -> Option<BuiltInEntry<'d>> {
        match self.built_in {
            Some(kind) => Some(BuiltInEntry { kind, entry: *self }),
            None => None,
        }
    }

    /// `schema`, else `schema_uri`.
    #[must_use]
    pub const fn schema(&self) -> Option<&'d str> {
        self.schema
    }
}

/// A `transaction_data_types` entry whose schema names a built-in type.
#[derive(Debug, Clone, Copy)]
pub struct BuiltInEntry<'d> {
    kind: Ts12Type,
    entry: TypeEntry<'d>,
}

impl<'d> BuiltInEntry<'d> {
    /// The built-in type.
    #[must_use]
    pub const fn kind(&self) -> Ts12Type {
        self.kind
    }

    /// Its claims metadata.
    #[must_use]
    pub const fn claims(&self) -> Option<&'d Node<'d>> {
        self.entry.claims
    }

    /// Its UI labels catalogue.
    #[must_use]
    pub const fn ui_labels(&self) -> Option<&'d Node<'d>> {
        self.entry.ui_labels
    }
}
