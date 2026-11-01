//! Claim values with their type, read from the format's own tree (C2).

use serde_json::Number;
use siros_codec::cbor::Value as Cbor;
use siros_codec::date::{Date, DateTime};
use siros_mdoc::Mdoc;
use siros_sdjwt::{Claim, ClaimValue, Element};

use crate::error::{CborTag, CredentialError};
use crate::tree::{Members as TreeMembers, TreeElement, TreeValue};

/// A claim value with its type.
#[derive(Clone, Copy)]
pub enum TypedValue<'a> {
    /// JSON `null`, CBOR `null`.
    Null,
    /// A boolean.
    Bool(bool),
    /// A JSON number without a fraction or exponent that fits 64 bits, or a CBOR integer.
    Integer(i128),
    /// Any other JSON number, as the credential writes it.
    Number(&'a Number),
    /// A JSON string, a CBOR text string.
    Text(&'a str),
    /// A CBOR byte string.
    Bytes(&'a [u8]),
    /// A CBOR `full-date`: tag 1004 over `YYYY-MM-DD`.
    FullDate(Date),
    /// A CBOR `tdate`: tag 0 over `YYYY-MM-DDThh:mm:ssZ`.
    DateTime(DateTime),
    /// An array.
    Array(Array<'a>),
    /// An object, or a CBOR map.
    Object(Object<'a>),
}

/// An array value.
#[derive(Clone, Copy)]
pub struct Array<'a>(ArrayOf<'a>);

#[derive(Clone, Copy)]
enum ArrayOf<'a> {
    Json(&'a [Element]),
    Cbor(&'a [Cbor]),
    Tree(&'a [TreeElement]),
}

/// An object value.
#[derive(Clone, Copy)]
pub struct Object<'a>(ObjectOf<'a>);

#[derive(Clone, Copy)]
enum ObjectOf<'a> {
    Json(&'a siros_sdjwt::Object),
    Cbor(&'a [(Cbor, Cbor)]),
    Tree(&'a TreeMembers),
}

impl<'a> Array<'a> {
    /// The elements the credential holds, in their order. An SD-JWT array element whose
    /// disclosure the credential lacks is absent.
    pub fn elements(&self) -> Elements<'a> {
        Elements(match self.0 {
            ArrayOf::Json(elements) => ElementsOf::Json(elements.iter()),
            ArrayOf::Cbor(items) => ElementsOf::Cbor(items.iter()),
            ArrayOf::Tree(elements) => ElementsOf::Tree(elements.iter()),
        })
    }
}

impl<'a> Object<'a> {
    /// The members the credential holds, each with its name, in their order.
    pub fn members(&self) -> Members<'a> {
        Members(match self.0 {
            ObjectOf::Json(object) => MembersOf::Json(Box::new(object.members())),
            ObjectOf::Cbor(entries) => MembersOf::Cbor(entries.iter()),
            ObjectOf::Tree(members) => MembersOf::Tree(Box::new(members.iter())),
        })
    }
}

/// The elements of an [`Array`].
pub struct Elements<'a>(ElementsOf<'a>);

enum ElementsOf<'a> {
    Json(std::slice::Iter<'a, Element>),
    Cbor(std::slice::Iter<'a, Cbor>),
    Tree(std::slice::Iter<'a, TreeElement>),
}

impl<'a> Iterator for Elements<'a> {
    type Item = TypedValue<'a>;

    fn next(&mut self) -> Option<TypedValue<'a>> {
        match &mut self.0 {
            ElementsOf::Json(elements) => elements
                .find_map(|element| match element {
                    Element::Present(claim) => Some(claim),
                    Element::Withheld => None,
                })
                .map(|claim| json(claim.value())),
            ElementsOf::Cbor(items) => items.next().map(cbor),
            ElementsOf::Tree(elements) => elements
                .find_map(|element| match element {
                    TreeElement::Present(value) => Some(value),
                    TreeElement::Withheld => None,
                })
                .map(TreeValue::typed),
        }
    }
}

/// The members of an [`Object`].
pub struct Members<'a>(MembersOf<'a>);

enum MembersOf<'a> {
    Json(Box<dyn Iterator<Item = (&'a str, &'a Claim)> + 'a>),
    Cbor(std::slice::Iter<'a, (Cbor, Cbor)>),
    Tree(Box<dyn Iterator<Item = (&'a str, &'a TreeValue)> + 'a>),
}

impl<'a> Iterator for Members<'a> {
    type Item = (&'a str, TypedValue<'a>);

    fn next(&mut self) -> Option<(&'a str, TypedValue<'a>)> {
        match &mut self.0 {
            MembersOf::Json(members) => members
                .next()
                .map(|(name, claim)| (name, json(claim.value()))),
            // Construction refuses a map with a key other than text.
            MembersOf::Cbor(entries) => entries.find_map(|(key, value)| match key {
                Cbor::Text(name) => Some((name.as_str(), cbor(value))),
                _ => None,
            }),
            MembersOf::Tree(members) => members.next().map(|(name, value)| (name, value.typed())),
        }
    }
}

/// The array of a claim tree's `elements`.
pub(crate) fn tree_array(elements: &[TreeElement]) -> TypedValue<'_> {
    TypedValue::Array(Array(ArrayOf::Tree(elements)))
}

/// The object of a claim tree's `members`.
pub(crate) fn tree_object(members: &TreeMembers) -> TypedValue<'_> {
    TypedValue::Object(Object(ObjectOf::Tree(members)))
}

/// The processed SD-JWT payload as an object.
pub(crate) fn payload(object: &siros_sdjwt::Object) -> TypedValue<'_> {
    TypedValue::Object(Object(ObjectOf::Json(object)))
}

/// The SD-JWT claim value `value`.
pub(crate) fn json(value: &ClaimValue) -> TypedValue<'_> {
    match value {
        ClaimValue::Null => TypedValue::Null,
        ClaimValue::Bool(b) => TypedValue::Bool(*b),
        ClaimValue::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => TypedValue::Integer(i128::from(i)),
            (None, Some(u)) => TypedValue::Integer(i128::from(u)),
            (None, None) => TypedValue::Number(n),
        },
        ClaimValue::String(s) => TypedValue::Text(s),
        ClaimValue::Array(elements) => TypedValue::Array(Array(ArrayOf::Json(elements))),
        ClaimValue::Object(object) => payload(object),
    }
}

/// The mdoc element value `value`.
pub(crate) fn cbor(value: &Cbor) -> TypedValue<'_> {
    classify(value).0
}

/// Every element value of `mdoc`, at every depth, has one of the ten types.
pub(crate) fn typed(mdoc: &Mdoc) -> Result<(), CredentialError> {
    mdoc.name_spaces()
        .iter()
        .flat_map(|name_space| name_space.items())
        .try_for_each(|item| check(item.value()))
}

fn check(value: &Cbor) -> Result<(), CredentialError> {
    if let (_, Some(broken)) = classify(value) {
        return Err(broken);
    }
    match value {
        Cbor::Array(items) => items.iter().try_for_each(check),
        Cbor::Map(entries) => entries.iter().try_for_each(|(_, value)| check(value)),
        _ => Ok(()),
    }
}

/// The type of `value`, and the rule `value` breaks when it has none of the ten types
/// (ISO/IEC 18013-5, 7.2.1: `tdate` is tag 0, `full-date` tag 1004). Such a value reads as
/// RFC 8949, Section 6.1 converts it to JSON: a tag as its content, `undefined` as `null`.
/// [`typed`] refuses it at construction.
fn classify(value: &Cbor) -> (TypedValue<'_>, Option<CredentialError>) {
    let typed = match value {
        Cbor::Unsigned(n) => TypedValue::Integer(i128::from(*n)),
        Cbor::Negative(n) => TypedValue::Integer(-1 - i128::from(*n)),
        Cbor::Bytes(b) => TypedValue::Bytes(b),
        Cbor::Text(t) => TypedValue::Text(t),
        Cbor::Array(items) => TypedValue::Array(Array(ArrayOf::Cbor(items))),
        Cbor::Map(entries) => {
            let object = TypedValue::Object(Object(ObjectOf::Cbor(entries)));
            let keys = entries.iter().all(|(key, _)| matches!(key, Cbor::Text(_)));
            return (object, (!keys).then_some(CredentialError::MapKey));
        }
        Cbor::Tag(1004, inner) => {
            return match inner.as_ref() {
                Cbor::Text(t) => Date::parse(t).map_or(
                    (TypedValue::Text(t), Some(CredentialError::FullDate)),
                    |d| (TypedValue::FullDate(d), None),
                ),
                other => (cbor(other), Some(CredentialError::FullDate)),
            }
        }
        Cbor::Tag(0, inner) => {
            return match inner.as_ref() {
                Cbor::Text(t) => DateTime::parse(t)
                    .map_or((TypedValue::Text(t), Some(CredentialError::Tdate)), |d| {
                        (TypedValue::DateTime(d), None)
                    }),
                other => (cbor(other), Some(CredentialError::Tdate)),
            }
        }
        Cbor::Tag(tag, inner) => {
            return (cbor(inner), Some(CredentialError::Tag(CborTag::new(*tag))))
        }
        Cbor::Bool(b) => TypedValue::Bool(*b),
        Cbor::Null => TypedValue::Null,
        Cbor::Encoded(_) => return (TypedValue::Null, Some(CredentialError::Undefined)),
    };
    (typed, None)
}
