//! JSON as requests, entries, records and registrations carry it: RFC 8259 text whose objects
//! name each member once (RFC 8259 §4 leaves a repeated name's meaning undefined). A [`Node`]
//! borrows its strings and number texts from the parsed text.

use std::borrow::Cow;
use std::fmt;

use serde::Deserialize;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;
use siros_explain::Explain;

mod python;

use python::PythonDouble;
pub use python::{PythonJson, PythonRepr, quote};

/// Why a text is no JSON with unique member names.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.json")]
pub enum JsonError {
    /// The text is no JSON value.
    #[error("{0}")]
    Syntax(#[explain(skip)] String),
    /// An object names a member twice: the first such name in code point order, of the first
    /// object to end that repeats one.
    #[error("an object repeats a member name: {0}")]
    DuplicateMember(#[explain(name = "member")] String),
}

impl From<serde_json::Error> for JsonError {
    fn from(error: serde_json::Error) -> Self {
        Self::Syntax(error.to_string())
    }
}

/// A JSON value borrowing from its text.
#[derive(Debug, Clone, PartialEq)]
pub enum Node<'a> {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, as written.
    Number(Number<'a>),
    /// A string.
    String(Cow<'a, str>),
    /// An array.
    Array(Vec<Node<'a>>),
    /// An object.
    Object(Object<'a>),
}

/// An object's members in text order, each name once. Two objects are equal when they hold the
/// same names with equal values, in any order.
#[derive(Debug, Clone, Default)]
pub struct Object<'a>(Vec<Member<'a>>);

impl PartialEq for Object<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .all(|member| other.get(&member.name) == Some(&member.value))
    }
}

/// One member of an [`Object`].
#[derive(Debug, Clone, PartialEq)]
pub struct Member<'a> {
    /// The member name.
    pub name: Cow<'a, str>,
    /// The member value.
    pub value: Node<'a>,
}

/// A JSON number as written. Two numbers are equal as Python's `json` reads them: integers by
/// value, other numbers as IEEE 754 doubles, an integer equal to integers alone.
#[derive(Debug, Clone)]
pub struct Number<'a>(Cow<'a, str>);

impl<'a> Node<'a> {
    /// Parses a JSON text whose objects name each member once.
    pub fn parse(text: &'a str) -> Result<Self, JsonError> {
        let raw: &'a RawValue = serde_json::from_str(text)?;
        Self::from_raw(raw)
    }

    /// Parses a JSON value already delimited by `serde_json`.
    pub fn from_raw(raw: &'a RawValue) -> Result<Self, JsonError> {
        let text = raw.get().trim_matches([' ', '\t', '\n', '\r']);
        match text.as_bytes().first() {
            Some(b'{') => Object::parse(text).map(Node::Object),
            Some(b'[') => {
                let items: Vec<&'a RawValue> = serde_json::from_str(text)?;
                items
                    .into_iter()
                    .map(Self::from_raw)
                    .collect::<Result<_, _>>()
                    .map(Node::Array)
            }
            Some(b'"') => Ok(Node::String(serde_json::from_str::<Text<'a>>(text)?.0)),
            Some(b't' | b'f') => Ok(Node::Bool(serde_json::from_str(text)?)),
            Some(b'n') => serde_json::from_str::<()>(text)
                .map(|()| Node::Null)
                .map_err(JsonError::from),
            _ => Ok(Node::Number(Number(Cow::Borrowed(text)))),
        }
    }

    /// The object of these members in their order; refused when a name repeats.
    pub fn object(
        members: impl IntoIterator<Item = (Cow<'a, str>, Node<'a>)>,
    ) -> Result<Self, JsonError> {
        Object::new(
            members
                .into_iter()
                .map(|(name, value)| Member { name, value })
                .collect(),
        )
        .map(Node::Object)
    }

    /// The value, owning its strings and number texts.
    #[must_use]
    pub fn into_owned(self) -> Node<'static> {
        match self {
            Node::Null => Node::Null,
            Node::Bool(value) => Node::Bool(value),
            Node::Number(number) => Node::Number(number.into_owned()),
            Node::String(text) => Node::String(Cow::Owned(text.into_owned())),
            Node::Array(items) => Node::Array(items.into_iter().map(Node::into_owned).collect()),
            Node::Object(object) => Node::Object(object.into_owned()),
        }
    }

    /// The string, when the value is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Node::String(text) => Some(text),
            _ => None,
        }
    }

    /// The object, when the value is one.
    #[must_use]
    pub fn as_object(&self) -> Option<&Object<'a>> {
        match self {
            Node::Object(object) => Some(object),
            _ => None,
        }
    }

    /// The array's items, when the value is one.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Node<'a>]> {
        match self {
            Node::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The member of that name, when the value is an object holding it.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Node<'a>> {
        self.as_object().and_then(|object| object.get(name))
    }
}

impl Node<'static> {
    /// The integer as a JSON number.
    #[must_use]
    pub fn integer(value: i128) -> Self {
        Node::Number(Number(Cow::Owned(value.to_string())))
    }
}

impl<'a> Object<'a> {
    fn parse(text: &'a str) -> Result<Self, JsonError> {
        let Members(raw) = serde_json::from_str(text)?;
        let members = raw
            .into_iter()
            .map(|(name, value)| Node::from_raw(value).map(|value| Member { name, value }))
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(name) = first_repeated(&members) {
            return Err(JsonError::DuplicateMember(name.to_owned()));
        }
        Ok(Object(members))
    }

    /// The object of one member.
    #[must_use]
    pub fn single(name: Cow<'a, str>, value: Node<'a>) -> Self {
        Object(vec![Member { name, value }])
    }

    /// The object of members whose names the caller wrote distinct.
    #[cfg(feature = "signed")]
    pub(crate) const fn distinct(members: Vec<Member<'a>>) -> Self {
        Object(members)
    }

    /// The object of these members in their order; refused when a name repeats.
    pub fn new(members: Vec<Member<'a>>) -> Result<Self, JsonError> {
        match first_repeated(&members) {
            Some(name) => Err(JsonError::DuplicateMember(name.to_owned())),
            None => Ok(Object(members)),
        }
    }

    /// The member of that name takes `value`, in its place; a new name comes last.
    pub fn set(&mut self, name: Cow<'a, str>, value: Node<'a>) {
        match self.0.iter_mut().find(|member| member.name == name) {
            Some(member) => member.value = value,
            None => self.0.push(Member { name, value }),
        }
    }

    /// The object without the members `keep` refuses.
    pub fn retain(&mut self, mut keep: impl FnMut(&Member<'a>) -> bool) {
        self.0.retain(|member| keep(member));
    }

    /// The object, owning its names, strings and number texts.
    #[must_use]
    pub fn into_owned(self) -> Object<'static> {
        Object(
            self.0
                .into_iter()
                .map(|Member { name, value }| Member {
                    name: Cow::Owned(name.into_owned()),
                    value: value.into_owned(),
                })
                .collect(),
        )
    }

    /// The value of the member of that name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Node<'a>> {
        self.0
            .iter()
            .find(|member| member.name == name)
            .map(|member| &member.value)
    }

    /// The members in text order.
    #[must_use]
    pub fn members(&self) -> &[Member<'a>] {
        &self.0
    }

    /// The member names in text order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|member| member.name.as_ref())
    }
}

/// What a [`Distinct`] tells its values apart by.
pub trait Named {
    /// The name.
    fn name(&self) -> &str;
}

impl Named for Member<'_> {
    fn name(&self) -> &str {
        &self.name
    }
}

/// The first repeated name in code point order, which is the order of the UTF-8 bytes.
fn first_repeated<T: Named>(values: &[T]) -> Option<&str> {
    let mut names: Vec<&str> = values.iter().map(T::name).collect();
    names.sort_unstable();
    names.windows(2).find_map(|pair| match pair {
        [a, b] if a == b => Some(*a),
        _ => None,
    })
}

/// A name a [`Distinct`] was given twice.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.json", id = "repeated_name")]
#[error("the name {name} repeats")]
pub struct RepeatedName {
    /// The name.
    pub name: String,
}

/// Values of distinct names, in their order. Each writes an [`Object`] member without a second
/// check of its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distinct<T>(Vec<T>);

impl<T> Default for Distinct<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T: Named> Distinct<T> {
    /// These values in their order.
    ///
    /// # Errors
    ///
    /// [`RepeatedName`]: the first repeated name in code point order.
    pub fn new(values: Vec<T>) -> Result<Self, RepeatedName> {
        match first_repeated(&values) {
            Some(name) => Err(RepeatedName {
                name: name.to_owned(),
            }),
            None => Ok(Self(values)),
        }
    }

    /// The values in their order.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// The value of that name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&T> {
        self.0.iter().find(|value| value.name() == name)
    }

    /// The object of a member per value, under the value's name.
    #[must_use]
    pub fn object<'a>(&self, mut value: impl FnMut(&T) -> Node<'a>) -> Object<'a> {
        Object(
            self.0
                .iter()
                .map(|item| Member {
                    name: Cow::Owned(item.name().to_owned()),
                    value: value(item),
                })
                .collect(),
        )
    }

    /// The object of a member per value, under the value's name.
    ///
    /// # Errors
    ///
    /// The first error of `value`.
    pub fn try_object<'a, E>(
        &self,
        mut value: impl FnMut(&T) -> Result<Node<'a>, E>,
    ) -> Result<Object<'a>, E> {
        self.0
            .iter()
            .map(|item| {
                Ok(Member {
                    name: Cow::Owned(item.name().to_owned()),
                    value: value(item)?,
                })
            })
            .collect::<Result<Vec<_>, E>>()
            .map(Object)
    }
}

/// Member names the build checked distinct: `field_names!` makes one.
#[derive(Debug, Clone, Copy)]
pub struct FieldNames<const N: usize>([&'static str; N]);

impl<const N: usize> FieldNames<N> {
    /// These names; `None` when one repeats.
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "each index stays below N, and const fn has no iterators"
    )]
    pub const fn new(names: [&'static str; N]) -> Option<Self> {
        let mut first = 0;
        while first < N {
            let mut second = first + 1;
            while second < N {
                if same_text(names[first], names[second]) {
                    return None;
                }
                second += 1;
            }
            first += 1;
        }
        Some(Self(names))
    }

    /// The object of a member per value present, each under the name at its position, in that
    /// order.
    #[must_use]
    pub fn object<'a>(&self, values: [Option<Node<'a>>; N]) -> Object<'a> {
        Object(
            self.0
                .into_iter()
                .zip(values)
                .filter_map(|(name, value)| {
                    Some(Member {
                        name: Cow::Borrowed(name),
                        value: value?,
                    })
                })
                .collect(),
        )
    }
}

#[allow(
    clippy::indexing_slicing,
    reason = "each index stays below the equal lengths, and const fn has no iterators"
)]
const fn same_text(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut at = 0;
    while at < a.len() {
        if a[at] != b[at] {
            return false;
        }
        at += 1;
    }
    true
}

/// The [`FieldNames`](crate::json::FieldNames) of these literals: a repeated name fails the build.
#[macro_export]
macro_rules! field_names {
    ($($name:literal),+ $(,)?) => {
        const {
            match $crate::json::FieldNames::new([$($name),+]) {
                ::core::option::Option::Some(names) => names,
                #[allow(
                    clippy::panic,
                    reason = "a panic in a constant fails the build (E0080)"
                )]
                ::core::option::Option::None => {
                    ::core::panic!("a member name repeats")
                }
            }
        }
    };
}

impl Number<'_> {
    /// The number, owning its text.
    #[must_use]
    pub fn into_owned(self) -> Number<'static> {
        Number(Cow::Owned(self.0.into_owned()))
    }

    /// The number as written.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }

    /// The number Python's `repr` writes for a finite double; `None` for an infinite one or NaN.
    #[must_use]
    pub fn of_double(value: f64) -> Option<Number<'static>> {
        value
            .is_finite()
            .then(|| Number(Cow::Owned(PythonDouble(value).to_string())))
    }

    /// Whether the number is an integer: written without a fraction or an exponent.
    #[must_use]
    pub fn is_integer(&self) -> bool {
        !self.0.contains(['.', 'e', 'E'])
    }

    /// Python's `float` of the value `json` reads: an integer rounded to the nearest double,
    /// `None` beyond the double range; another number as its double.
    #[must_use]
    pub fn to_double(&self) -> Option<f64> {
        match self.integer() {
            Some(digits) => digits.parse::<f64>().ok().filter(|value| value.is_finite()),
            None => self.double(),
        }
    }

    /// The integer's digits without a sign for zero, when the number is an integer.
    fn integer(&self) -> Option<&str> {
        self.is_integer()
            .then(|| if self.0 == "-0" { "0" } else { self.text() })
    }

    /// The double nearest to a non-integer number; infinite beyond the double range.
    fn double(&self) -> Option<f64> {
        if self.is_integer() {
            None
        } else {
            self.0.parse().ok()
        }
    }

    /// The value as a `u64`, when it is an integer in range.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        self.integer().and_then(|digits| digits.parse().ok())
    }
}

impl PartialEq for Number<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self.integer(), other.integer()) {
            (Some(a), Some(b)) => a == b,
            (None, None) => self.double() == other.double(),
            _ => false,
        }
    }
}

/// A JSON string borrowed from the text when it holds no escape.
struct Text<'a>(Cow<'a, str>);

impl<'de: 'a, 'a> Deserialize<'de> for Text<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(TextVisitor)
    }
}

struct TextVisitor;

impl<'de> Visitor<'de> for TextVisitor {
    type Value = Text<'de>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_borrowed_str<E>(self, text: &'de str) -> Result<Self::Value, E> {
        Ok(Text(Cow::Borrowed(text)))
    }

    fn visit_str<E>(self, text: &str) -> Result<Self::Value, E> {
        Ok(Text(Cow::Owned(text.to_owned())))
    }
}

/// An object's members as written, values still unparsed.
struct Members<'a>(Vec<(Cow<'a, str>, &'a RawValue)>);

impl<'de: 'a, 'a> Deserialize<'de> for Members<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(MembersVisitor)
    }
}

struct MembersVisitor;

impl<'de> Visitor<'de> for MembersVisitor {
    type Value = Members<'de>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut members = Vec::new();
        while let Some(Text(name)) = map.next_key()? {
            members.push((name, map.next_value::<&'de RawValue>()?));
        }
        Ok(Members(members))
    }
}

/// An object's members as written, each name once, values still unparsed.
#[derive(Debug, Clone)]
pub struct RawObject<'a>(Vec<(Cow<'a, str>, &'a RawValue)>);

impl<'a> RawObject<'a> {
    /// Parses an object, refusing a repeated member name at its own level.
    pub fn parse(text: &'a str) -> Result<Self, JsonError> {
        let Members(members) = serde_json::from_str(text)?;
        let mut names: Vec<&str> = members.iter().map(|(name, _)| name.as_ref()).collect();
        names.sort_unstable();
        if let Some([name, _]) = names
            .windows(2)
            .find(|pair| matches!(pair, [a, b] if a == b))
        {
            return Err(JsonError::DuplicateMember((*name).to_owned()));
        }
        Ok(Self(members))
    }

    /// The raw value of the member of that name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&'a RawValue> {
        self.0
            .iter()
            .find(|(member, _)| member == name)
            .map(|(_, value)| *value)
    }

    /// The members in text order.
    pub fn members(&self) -> impl Iterator<Item = (&str, &'a RawValue)> {
        self.0.iter().map(|(name, value)| (name.as_ref(), *value))
    }
}

/// Parses a JSON string value borrowing from its text when it holds no escape.
pub fn string(raw: &RawValue) -> Result<Cow<'_, str>, JsonError> {
    serde_json::from_str::<Text<'_>>(raw.get())
        .map(|Text(text)| text)
        .map_err(JsonError::from)
}
