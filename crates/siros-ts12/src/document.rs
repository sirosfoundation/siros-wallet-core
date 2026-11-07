//! The registration document `ts12`: the credential's own type metadata's `category` and
//! `transaction_data_types`, each `claims_uri` and `ui_labels_uri` replaced by the document fetched
//! (TS12 §4.1, §4.1.1).

use std::borrow::Cow;
use std::fmt;

use siros_explain::{Explain, IntoArg, Keyed, kind};
use siros_openid4vp::ids::{DocumentKey, TransactionType};
use siros_openid4vp::json::{JsonError, Node, Object};
use siros_openid4vp::known_object;
use siros_openid4vp::plugins::JsonText;
use siros_openid4vp::rows::HttpsUrl;
use siros_openid4vp::wallet::DocumentBytes;
use siros_paso::rulebook::{Family, PasoType};

/// The key of the TS12 document in a credential's registration.
pub const DOCUMENT: DocumentKey<'static> = siros_explain::checked!(DocumentKey, "ts12");
/// TS12 §3: the category of an SCA attestation.
const SCA_CATEGORY: &str = "urn:eu:europa:ec:eudi:sua:sca";

const PAYMENT: &str = "urn:eudi:sca:payment:1";
const LOGIN_RISK: &str = "urn:eudi:sca:login_risk_transaction:1";

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
    pub fn of(kind: &TransactionType<'_>) -> Option<Self> {
        match kind.as_str() {
            PAYMENT => Some(Self::Payment),
            LOGIN_RISK => Some(Self::LoginRisk),
            _ => None,
        }
    }

    /// Its URN.
    pub(crate) const fn urn(self) -> &'static str {
        match self {
            Self::Payment => PAYMENT,
            Self::LoginRisk => LOGIN_RISK,
        }
    }

    /// The type as siros-paso's engine renders it: a payment by its payment rulebook, an action by
    /// its view.
    #[must_use]
    pub const fn paso_type(self) -> PasoType<'static> {
        PasoType::rendered_by(
            self.urn(),
            match self {
                Self::Payment => Family::Payment,
                Self::LoginRisk => Family::View,
            },
        )
    }
}

/// A member TS12 §4.1 lets a type write inline or by a `_uri` twin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwinnedMember {
    /// `schema`, beside `schema_uri`.
    Schema,
    /// `claims`, beside `claims_uri`.
    Claims,
    /// `ui_labels`, beside `ui_labels_uri`.
    UiLabels,
}

impl TwinnedMember {
    /// The member's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Schema => "schema",
            Self::Claims => "claims",
            Self::UiLabels => "ui_labels",
        }
    }

    const fn uri(self) -> &'static str {
        match self {
            Self::Schema => "schema_uri",
            Self::Claims => "claims_uri",
            Self::UiLabels => "ui_labels_uri",
        }
    }
}

impl fmt::Display for TwinnedMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A member is named as the code fixes it.
impl IntoArg for TwinnedMember {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.name()
    }
}

/// Type metadata the registration cannot compose, or a document it cannot read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "ts12.compose")]
pub enum ComposeError {
    /// `transaction_data_types` absent, or no object of objects.
    #[error("transaction_data_types is absent or no object of objects")]
    Types,
    /// A member and its `_uri` twin both present (TS12 §4.1).
    #[error("{member}: a member and its _uri twin are both present")]
    Both {
        /// The member.
        member: TwinnedMember,
    },
    /// A `_uri` member naming a document the caller did not fetch.
    #[error("{uri} names a document the caller did not fetch")]
    Unfetched {
        /// The URI as written.
        uri: String,
    },
}

/// A document the caller fetched at registration for a `claims_uri` or `ui_labels_uri`: a JSON
/// value with unique member names at every level.
#[derive(Debug, Clone, PartialEq)]
pub struct FetchedDocument(Node<'static>);

impl FetchedDocument {
    /// The document these bytes hold.
    ///
    /// # Errors
    ///
    /// [`JsonError`]: the bytes are no such JSON.
    pub fn parse(bytes: &[u8]) -> Result<Self, JsonError> {
        let text = std::str::from_utf8(bytes).map_err(|e| JsonError::Syntax(e.to_string()))?;
        Ok(Self(Node::parse(text)?.into_owned()))
    }
}

/// What [`Ts12Document::compose`] writes: a credential registration's `ts12` document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposedDocument(Vec<u8>);

impl ComposedDocument {
    /// The content under the key [`DOCUMENT`].
    #[must_use]
    pub fn content(&self) -> DocumentBytes<'_> {
        DocumentBytes::new(&self.0)
    }
}

/// A document's `category`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// TS12 §3's category of an SCA attestation.
    Sca,
    /// Absent, or any other.
    Other,
}

/// A `schema` or `schema_uri` as an entry writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrittenSchema<'d>(&'d str);

impl<'d> WrittenSchema<'d> {
    /// The text.
    #[must_use]
    pub const fn as_str(self) -> &'d str {
        self.0
    }
}

/// A credential's registration document.
#[derive(Debug, Clone)]
pub struct Ts12Document<'d> {
    category: Category,
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
    /// `_uri` twin, or a fetched document is missing.
    pub fn compose(
        own: &Node<'_>,
        fetched: &Keyed<HttpsUrl, FetchedDocument>,
    ) -> Result<ComposedDocument, ComposeError> {
        let types = own
            .get("transaction_data_types")
            .and_then(Node::as_object)
            .ok_or(ComposeError::Types)?;
        let mut composed = types.clone().into_owned();
        for member in types.members() {
            composed.set(
                Cow::Owned(member.name.to_string()),
                composed_type(&member.value, fetched)?,
            );
        }
        let document = known_object! {
            "category" => own.get("category").map(|category| category.clone().into_owned()),
            "transaction_data_types" => Some(Node::Object(composed)),
        };
        Ok(ComposedDocument(
            JsonText::from(&Node::Object(document))
                .as_str()
                .as_bytes()
                .to_vec(),
        ))
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
            category: match node.get("category").and_then(Node::as_str) {
                Some(SCA_CATEGORY) => Category::Sca,
                _ => Category::Other,
            },
            types,
        })
    }

    /// `category`.
    #[must_use]
    pub const fn category(&self) -> Category {
        self.category
    }

    /// The entry of a type key.
    #[must_use]
    pub fn entry(&self, kind: &TransactionType<'_>) -> Option<TypeEntry<'d>> {
        self.listed(kind.as_str(), Ts12Type::of(kind))
    }

    /// The entry of a built-in type's URN, when its schema names that type.
    #[must_use]
    pub fn built_in(&self, kind: Ts12Type) -> Option<BuiltInEntry<'d>> {
        self.listed(kind.urn(), Some(kind))?.built_in()
    }

    fn listed(&self, key: &str, built_in: Option<Ts12Type>) -> Option<TypeEntry<'d>> {
        let entry = self.types.get(key)?;
        let schema = entry
            .get("schema")
            .or_else(|| entry.get("schema_uri"))
            .and_then(Node::as_str);
        Some(TypeEntry {
            built_in: built_in.filter(|built_in| schema == Some(built_in.urn())),
            schema: schema.map(WrittenSchema),
            claims: entry.get("claims"),
            ui_labels: entry.get("ui_labels"),
        })
    }
}

/// The type's members with each fetched member replaced by the document it names.
fn composed_type(
    entry: &Node<'_>,
    fetched: &Keyed<HttpsUrl, FetchedDocument>,
) -> Result<Node<'static>, ComposeError> {
    use TwinnedMember::{Claims, Schema, UiLabels};
    let object = entry.as_object().ok_or(ComposeError::Types)?;
    if let Some(member) = [Schema, Claims, UiLabels]
        .into_iter()
        .find(|twin| object.get(twin.uri()).is_some() && object.get(twin.name()).is_some())
    {
        return Err(ComposeError::Both { member });
    }
    let mut composed = object.clone().into_owned();
    for twin in [Claims, UiLabels] {
        if let Some(uri) = object.get(twin.uri()) {
            composed.retain(|member| member.name != twin.uri());
            composed.set(Cow::Borrowed(twin.name()), document_at(uri, fetched)?);
        }
    }
    Ok(Node::Object(composed))
}

/// The document a `_uri` member names, as the caller fetched it.
fn document_at(
    uri: &Node<'_>,
    fetched: &Keyed<HttpsUrl, FetchedDocument>,
) -> Result<Node<'static>, ComposeError> {
    let unfetched = || ComposeError::Unfetched {
        uri: uri
            .as_str()
            .map_or_else(|| uri.json_compact().to_string(), str::to_owned),
    };
    let url = uri
        .as_str()
        .and_then(|text| HttpsUrl::parse(text).ok())
        .ok_or_else(unfetched)?;
    fetched
        .get(&url)
        .map(|document| document.0.clone())
        .ok_or_else(unfetched)
}

/// One `transaction_data_types` entry: the built-in type its `schema` or `schema_uri` names, its
/// claims metadata (TS12 §3.3.2) and its UI labels catalogue (TS12 §3.3.3).
#[derive(Debug, Clone, Copy)]
pub struct TypeEntry<'d> {
    built_in: Option<Ts12Type>,
    schema: Option<WrittenSchema<'d>>,
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
    pub const fn schema(&self) -> Option<WrittenSchema<'d>> {
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
