//! Response members: what a transaction's profile writes into a presentation beside the members
//! the format's proof writes itself.

use std::borrow::Cow;
use std::fmt;

use siros_explain::Explain;

use crate::json::{JsonError, Node};

/// A member's name in a presentation's proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Member {
    /// A claim of a JSON proof, such as a Key Binding JWT claim.
    Claim(Cow<'static, str>),
    /// A data element of an mdoc's `DeviceSigned` name spaces.
    Element {
        /// The name space.
        namespace: Cow<'static, str>,
        /// The data element identifier.
        element: Cow<'static, str>,
    },
}

impl Member {
    /// A claim named by a static string.
    #[must_use]
    pub const fn claim(name: &'static str) -> Self {
        Self::Claim(Cow::Borrowed(name))
    }

    /// A data element named by static strings.
    #[must_use]
    pub const fn element(namespace: &'static str, element: &'static str) -> Self {
        Self::Element {
            namespace: Cow::Borrowed(namespace),
            element: Cow::Borrowed(element),
        }
    }
}

impl fmt::Display for Member {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Claim(name) => f.write_str(name),
            Self::Element { namespace, element } => write!(f, "({namespace}, {element})"),
        }
    }
}

/// A member's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberValue {
    /// A text string.
    Text(String),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A JSON value, which a proof writes as its text.
    Json(JsonText),
    /// A CBOR data item in its encoding, which a CBOR proof embeds as the element's value.
    Cbor(Item),
}

/// One CBOR data item in its encoding, its keys distinct at every depth; only `Item::parse`,
/// through `cbor::decode`, makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item(Vec<u8>);

impl Item {
    /// The item; refused for bytes that are no one data item with distinct keys at every depth.
    ///
    /// # Errors
    ///
    /// `cbor::decode` refuses the bytes.
    #[cfg(feature = "cbor")]
    pub fn parse(bytes: Vec<u8>) -> Result<Self, crate::cbor::CborError> {
        crate::cbor::decode(&bytes).map(|_| Self(bytes))
    }

    /// The encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The text of a JSON value whose objects name each member once, as [`Node::json_compact`] writes
/// it: object members in their order, each number as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonText(String);

impl JsonText {
    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The text of a JSON value given as text.
    pub fn parse(text: &str) -> Result<Self, JsonError> {
        Node::parse(text).map(|node| Self::from(&node))
    }
}

impl From<&Node<'_>> for JsonText {
    fn from(node: &Node<'_>) -> Self {
        Self(node.json_compact().to_string())
    }
}

/// A response's members in the order written, each name once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Members(Vec<(Member, MemberValue)>);

/// A member written twice into one presentation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(id = "member_twice")]
#[error("the member {0} is written twice")]
pub struct MemberTwice(#[explain(skip)] pub Member);

impl Members {
    /// The members, each name once.
    pub fn new(members: Vec<(Member, MemberValue)>) -> Result<Self, MemberTwice> {
        if let Some((twice, _)) = members.iter().enumerate().find_map(|(k, (m, v))| {
            members
                .iter()
                .take(k)
                .any(|(n, _)| n == m)
                .then_some((m, v))
        }) {
            return Err(MemberTwice(twice.clone()));
        }
        Ok(Self(members))
    }

    /// No member.
    #[must_use]
    pub const fn none() -> Self {
        Self(Vec::new())
    }

    /// The members in the order written.
    pub fn iter(&self) -> std::slice::Iter<'_, (Member, MemberValue)> {
        self.0.iter()
    }

    /// The member names in the order written.
    pub fn names(&self) -> impl Iterator<Item = &Member> {
        self.0.iter().map(|(member, _)| member)
    }
}
