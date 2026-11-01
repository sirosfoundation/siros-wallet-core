//! A credential's claims apart from its format: the typed claim tree a registration projection
//! carries to the credential picker (K1), read with the pointers and the types of the stored
//! credential (C2, C3).

use std::fmt;

use serde_json::Number;
use siros_codec::cbor::{Item, Kind, Value as Cbor};
use siros_codec::date::{Date, DateTime};
use siros_dcql::{mdoc_components, resolve, ClaimNode, ClaimPath, Lookup, PathError};
use siros_sdjwt::{Claim, ClaimValue, Element};

use crate::credential::{Body, Credential, Format};
use crate::value::{self, TypedValue};

/// The CBOR tag of a JSON number with a fraction or an exponent: the bytes of its JSON text
/// (tag 262, embedded JSON).
const JSON_NUMBER: u64 = 262;
/// The CBOR tag of a `tdate` (RFC 8949, Section 3.4.1).
const TDATE: u64 = 0;
/// The CBOR tag of a `full-date` (RFC 8943).
const FULL_DATE: u64 = 1004;

/// The claims of a credential with their types: the processed payload of an SD-JWT VC, its
/// array positions kept, or the namespaces of an mdoc with their elements.
///
/// Two trees are equal when they hold the same claims in the same format: their CBOR forms
/// encode alike, the deterministic encoding ordering each object's members.
pub struct ClaimTree {
    format: Format,
    root: Members,
}

impl PartialEq for ClaimTree {
    fn eq(&self, other: &Self) -> bool {
        self.format == other.format && self.to_cbor().encode() == other.to_cbor().encode()
    }
}

impl Eq for ClaimTree {}

impl fmt::Debug for ClaimTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaimTree")
            .field("format", &self.format)
            .field("claims", &self.to_cbor())
            .finish()
    }
}

/// A claim value of a [`ClaimTree`].
pub(crate) enum TreeValue {
    Null,
    Bool(bool),
    Integer(Integer),
    Number(Number),
    Text(String),
    Bytes(Vec<u8>),
    FullDate(Date),
    DateTime(DateTime),
    Array(Vec<TreeElement>),
    Object(Members),
}

/// An integer as CBOR holds it: major type 0, or major type 1 with the value `-1 - n`.
#[derive(Clone, Copy)]
pub(crate) enum Integer {
    Unsigned(u64),
    Negative(u64),
}

/// An array position: a present element, or one the stored credential withholds.
pub(crate) enum TreeElement {
    Present(TreeValue),
    Withheld,
}

/// The members of an object, each name once, in their order.
pub(crate) struct Members(Vec<(String, TreeValue)>);

/// Why a CBOR item is no claim tree of a registration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum TreeError {
    /// The root is no map, or an mdoc namespace is no map.
    Root,
    /// A map key is no text string, or a map repeats a key.
    MapKey,
    /// An item carries this tag, which a claim value has none of.
    Tag(u64),
    /// A tag-0 item is no `tdate` text.
    DateTime,
    /// A tag-1004 item is no `full-date` text.
    FullDate,
    /// A tag-262 item is no JSON number with a fraction or an exponent.
    Number,
    /// `undefined` stands outside an array, where it marks a withheld position.
    Withheld,
    /// A stored integer lies outside the range of CBOR's major types 0 and 1.
    IntegerRange,
}

impl TreeError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Root => "claim_tree_root",
            Self::MapKey => "claim_tree_map_key",
            Self::Tag(_) => "claim_tree_tag",
            Self::DateTime => "claim_tree_tdate",
            Self::FullDate => "claim_tree_full_date",
            Self::Number => "claim_tree_number",
            Self::Withheld => "claim_tree_withheld",
            Self::IntegerRange => "claim_tree_integer_range",
        }
    }
}

impl ClaimTree {
    /// The claims of `credential`: an SD-JWT VC's processed payload, every member of every
    /// object and every issued array position, or an mdoc's namespaces with their elements.
    ///
    /// # Errors
    ///
    /// [`TreeError::IntegerRange`] for an integer CBOR holds in neither major type 0 nor 1.
    pub fn of(credential: &Credential) -> Result<Self, TreeError> {
        let root = match &credential.body {
            Body::SdJwtVc(vc) => json_members(vc.sd_jwt().claims().members())?,
            Body::Mdoc(mdoc) => Members(
                mdoc.name_spaces()
                    .iter()
                    .map(|name_space| {
                        let elements = name_space
                            .items()
                            .iter()
                            .map(|item| {
                                let name = item.identifier().as_str().to_owned();
                                Ok((name, typed(value::cbor(item.value()))?))
                            })
                            .collect::<Result<_, TreeError>>()?;
                        let name = name_space.name().as_str().to_owned();
                        Ok((name, TreeValue::Object(Members(elements))))
                    })
                    .collect::<Result<_, TreeError>>()?,
            ),
        };
        Ok(Self {
            format: credential.format(),
            root,
        })
    }

    /// The tree without the claims named `names`: an SD-JWT VC's top-level claims, or an mdoc's
    /// elements in every namespace.
    #[must_use]
    pub fn without(self, names: &[&str]) -> Self {
        let kept = |members: Members| {
            Members(
                members
                    .0
                    .into_iter()
                    .filter(|(name, _)| !names.contains(&name.as_str()))
                    .collect(),
            )
        };
        let root = match self.format {
            Format::SdJwtVc => kept(self.root),
            Format::Mdoc => Members(
                self.root
                    .0
                    .into_iter()
                    .map(|(name_space, elements)| match elements {
                        TreeValue::Object(elements) => {
                            (name_space, TreeValue::Object(kept(elements)))
                        }
                        other => (name_space, other),
                    })
                    .collect(),
            ),
        };
        Self {
            format: self.format,
            root,
        }
    }

    /// The format whose pointers address the tree.
    #[must_use]
    pub fn format(&self) -> Format {
        self.format
    }

    /// The values of the claims `path` selects, as [`Credential::claims`] selects them in the
    /// stored credential.
    ///
    /// # Errors
    ///
    /// [`PathError`] when the path does not fit the tree or selects nothing.
    pub fn claims(&self, path: &ClaimPath) -> Result<Vec<TypedValue<'_>>, PathError> {
        let root = Node::Root(&self.root);
        match self.format {
            Format::SdJwtVc => Ok(resolve(root, path)?.into_iter().map(Node::typed).collect()),
            Format::Mdoc => {
                let (name_space, identifier) = mdoc_components(path)?;
                self.root
                    .get(name_space)
                    .and_then(|elements| match elements {
                        TreeValue::Object(elements) => elements.get(identifier),
                        _ => None,
                    })
                    .map(|value| vec![value.typed()])
                    .ok_or(PathError::Empty)
            }
        }
    }

    /// The tree as CBOR: maps with text keys, tag 0 over a `tdate`, tag 1004 over a
    /// `full-date`, tag 262 over the JSON text of a number with a fraction or an exponent, and
    /// `undefined` at a withheld array position.
    #[must_use]
    pub fn to_cbor(&self) -> Cbor {
        self.root.to_cbor()
    }

    /// The tree of `format` that `item` encodes, as [`ClaimTree::to_cbor`] writes it.
    ///
    /// # Errors
    ///
    /// [`TreeError`]: the first rule `item` breaks.
    pub fn from_cbor(format: Format, item: &Item<'_>) -> Result<Self, TreeError> {
        let root = Members::from_cbor(item)?;
        if format == Format::Mdoc
            && root
                .0
                .iter()
                .any(|(_, elements)| !matches!(elements, TreeValue::Object(_)))
        {
            return Err(TreeError::Root);
        }
        Ok(Self { format, root })
    }
}

impl Members {
    fn get(&self, name: &str) -> Option<&TreeValue> {
        self.0
            .iter()
            .find(|(member, _)| member == name)
            .map(|(_, value)| value)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, &TreeValue)> {
        self.0.iter().map(|(name, value)| (name.as_str(), value))
    }

    fn to_cbor(&self) -> Cbor {
        Cbor::Map(
            self.0
                .iter()
                .map(|(name, value)| (Cbor::text(name), value.to_cbor()))
                .collect(),
        )
    }

    fn from_cbor(item: &Item<'_>) -> Result<Self, TreeError> {
        let entries = item.as_map().ok_or(TreeError::Root)?;
        entries
            .iter()
            .map(|(key, value)| {
                let name = key.as_text().ok_or(TreeError::MapKey)?;
                Ok((name.to_owned(), TreeValue::from_cbor(value)?))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }
}

impl TreeValue {
    /// The value with its type.
    pub(crate) fn typed(&self) -> TypedValue<'_> {
        match self {
            Self::Null => TypedValue::Null,
            Self::Bool(b) => TypedValue::Bool(*b),
            Self::Integer(Integer::Unsigned(n)) => TypedValue::Integer(i128::from(*n)),
            Self::Integer(Integer::Negative(n)) => TypedValue::Integer(-1 - i128::from(*n)),
            Self::Number(n) => TypedValue::Number(n),
            Self::Text(t) => TypedValue::Text(t),
            Self::Bytes(b) => TypedValue::Bytes(b),
            Self::FullDate(d) => TypedValue::FullDate(*d),
            Self::DateTime(t) => TypedValue::DateTime(*t),
            Self::Array(elements) => value::tree_array(elements),
            Self::Object(members) => value::tree_object(members),
        }
    }

    fn to_cbor(&self) -> Cbor {
        match self {
            Self::Null => Cbor::Null,
            Self::Bool(b) => Cbor::Bool(*b),
            Self::Integer(Integer::Unsigned(n)) => Cbor::Unsigned(*n),
            Self::Integer(Integer::Negative(n)) => Cbor::Negative(*n),
            Self::Number(n) => Cbor::Tag(
                JSON_NUMBER,
                Box::new(Cbor::Bytes(n.to_string().into_bytes())),
            ),
            Self::Text(t) => Cbor::text(t),
            Self::Bytes(b) => Cbor::Bytes(b.clone()),
            Self::FullDate(d) => Cbor::Tag(FULL_DATE, Box::new(Cbor::Text(d.to_string()))),
            Self::DateTime(t) => Cbor::Tag(TDATE, Box::new(Cbor::Text(t.to_string()))),
            Self::Array(elements) => Cbor::Array(
                elements
                    .iter()
                    .map(|element| match element {
                        TreeElement::Present(value) => value.to_cbor(),
                        TreeElement::Withheld => Cbor::Encoded(vec![UNDEFINED]),
                    })
                    .collect(),
            ),
            Self::Object(members) => members.to_cbor(),
        }
    }

    fn from_cbor(item: &Item<'_>) -> Result<Self, TreeError> {
        Ok(match item.kind() {
            Kind::Null => Self::Null,
            Kind::Bool(b) => Self::Bool(*b),
            Kind::Unsigned(n) => Self::Integer(Integer::Unsigned(*n)),
            Kind::Negative(n) => Self::Integer(Integer::Negative(*n)),
            Kind::Text(t) => Self::Text((*t).to_owned()),
            Kind::Bytes(b) => Self::Bytes(b.to_vec()),
            Kind::Array(items) => Self::Array(
                items
                    .iter()
                    .map(|item| match item.kind() {
                        Kind::Undefined => Ok(TreeElement::Withheld),
                        _ => Self::from_cbor(item).map(TreeElement::Present),
                    })
                    .collect::<Result<_, _>>()?,
            ),
            Kind::Map(_) => Self::Object(Members::from_cbor(item)?),
            Kind::Tag(FULL_DATE, inner) => Self::FullDate(
                inner
                    .as_text()
                    .and_then(Date::parse)
                    .ok_or(TreeError::FullDate)?,
            ),
            Kind::Tag(TDATE, inner) => Self::DateTime(
                inner
                    .as_text()
                    .and_then(DateTime::parse)
                    .ok_or(TreeError::DateTime)?,
            ),
            Kind::Tag(JSON_NUMBER, inner) => Self::Number(json_number(inner)?),
            Kind::Tag(tag, _) => return Err(TreeError::Tag(*tag)),
            Kind::Undefined => return Err(TreeError::Withheld),
        })
    }
}

/// The CBOR simple value `undefined`.
const UNDEFINED: u8 = 0xf7;

/// The JSON number with a fraction or an exponent whose text `item` carries.
fn json_number(item: &Item<'_>) -> Result<Number, TreeError> {
    let text = item
        .as_bytes()
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .ok_or(TreeError::Number)?;
    let number: Number = text.parse().map_err(|_| TreeError::Number)?;
    if number.is_i64() || number.is_u64() {
        return Err(TreeError::Number);
    }
    Ok(number)
}

/// The tree value of a stored claim value, read with its type.
fn typed(value: TypedValue<'_>) -> Result<TreeValue, TreeError> {
    Ok(match value {
        TypedValue::Null => TreeValue::Null,
        TypedValue::Bool(b) => TreeValue::Bool(b),
        TypedValue::Integer(i) => TreeValue::Integer(integer(i)?),
        TypedValue::Number(n) => TreeValue::Number(n.clone()),
        TypedValue::Text(t) => TreeValue::Text(t.to_owned()),
        TypedValue::Bytes(b) => TreeValue::Bytes(b.to_vec()),
        TypedValue::FullDate(d) => TreeValue::FullDate(d),
        TypedValue::DateTime(t) => TreeValue::DateTime(t),
        TypedValue::Array(array) => TreeValue::Array(
            array
                .elements()
                .map(|element| typed(element).map(TreeElement::Present))
                .collect::<Result<_, _>>()?,
        ),
        TypedValue::Object(object) => TreeValue::Object(Members(
            object
                .members()
                .map(|(name, value)| Ok((name.to_owned(), typed(value)?)))
                .collect::<Result<_, TreeError>>()?,
        )),
    })
}

/// The integer `i` in CBOR's major type 0 or 1.
fn integer(i: i128) -> Result<Integer, TreeError> {
    match u64::try_from(i) {
        Ok(n) => Ok(Integer::Unsigned(n)),
        Err(_) => u64::try_from(-1 - i)
            .map(Integer::Negative)
            .map_err(|_| TreeError::IntegerRange),
    }
}

/// The members of an SD-JWT object, its arrays at their issued positions.
fn json_members<'a>(
    members: impl Iterator<Item = (&'a str, &'a Claim)>,
) -> Result<Members, TreeError> {
    members
        .map(|(name, claim)| Ok((name.to_owned(), json_value(claim.value())?)))
        .collect::<Result<_, _>>()
        .map(Members)
}

/// The tree value of an SD-JWT claim value.
fn json_value(value: &ClaimValue) -> Result<TreeValue, TreeError> {
    Ok(match value {
        ClaimValue::Array(elements) => TreeValue::Array(
            elements
                .iter()
                .map(|element| match element {
                    Element::Present(claim) => json_value(claim.value()).map(TreeElement::Present),
                    Element::Withheld => Ok(TreeElement::Withheld),
                })
                .collect::<Result<_, _>>()?,
        ),
        ClaimValue::Object(object) => TreeValue::Object(json_members(object.members())?),
        scalar => typed(value::json(scalar))?,
    })
}

/// A node of the tree as a claims path pointer walks it (Q4).
#[derive(Clone, Copy)]
enum Node<'a> {
    Root(&'a Members),
    Value(&'a TreeValue),
}

impl<'a> Node<'a> {
    fn typed(self) -> TypedValue<'a> {
        match self {
            Self::Root(members) => value::tree_object(members),
            Self::Value(value) => value.typed(),
        }
    }

    fn members(self) -> Option<&'a Members> {
        match self {
            Self::Root(members) | Self::Value(TreeValue::Object(members)) => Some(members),
            Self::Value(_) => None,
        }
    }

    fn array(self) -> Option<&'a [TreeElement]> {
        match self {
            Self::Value(TreeValue::Array(elements)) => Some(elements),
            Self::Root(_) | Self::Value(_) => None,
        }
    }
}

impl<'a> ClaimNode for Node<'a> {
    type Elements = std::iter::FilterMap<
        std::slice::Iter<'a, TreeElement>,
        fn(&'a TreeElement) -> Option<Node<'a>>,
    >;

    fn member(&self, key: &str) -> Lookup<Self> {
        match self.members() {
            Some(members) => members
                .get(key)
                .map_or(Lookup::Absent, |value| Lookup::Found(Node::Value(value))),
            None => Lookup::WrongKind,
        }
    }

    fn element(&self, index: u64) -> Lookup<Self> {
        let Some(elements) = self.array() else {
            return Lookup::WrongKind;
        };
        match usize::try_from(index).ok().and_then(|i| elements.get(i)) {
            Some(TreeElement::Present(value)) => Lookup::Found(Node::Value(value)),
            Some(TreeElement::Withheld) | None => Lookup::Absent,
        }
    }

    fn elements(&self) -> Option<Self::Elements> {
        let present: fn(&'a TreeElement) -> Option<Node<'a>> = |element| match element {
            TreeElement::Present(value) => Some(Node::Value(value)),
            TreeElement::Withheld => None,
        };
        self.array()
            .map(|elements| elements.iter().filter_map(present))
    }
}
