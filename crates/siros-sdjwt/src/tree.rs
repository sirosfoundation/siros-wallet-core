//! The processed claims of an issued SD-JWT, each node with the disclosure that reveals it. An
//! array keeps its issued positions (SD-JWT VC §9.1.2: a path addresses a claim "as if all
//! selectively disclosable claims were disclosed"). An array digest without a disclosure, a decoy
//! among them, is an [`Element::Withheld`] at its position.

use std::borrow::Cow;

use siros_explain::{IntoArg, Kind};
use siros_openid4vp::json::{JsonError, Node, Number};

use crate::alg::Digest;
use crate::process::ELLIPSIS;

/// A JSON object of the processed payload: its permanently disclosed members in issued order,
/// then the members its disclosures add, in the order of its `_sd` digests.
#[derive(Default)]
pub struct Object {
    members: Vec<Member>,
}

struct Member {
    name: String,
    claim: IssuedClaim,
}

impl Object {
    pub(crate) fn push(&mut self, name: String, claim: IssuedClaim) {
        self.members.push(Member { name, claim });
    }

    /// The member named `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&IssuedClaim> {
        self.members
            .iter()
            .find(|m| m.name == name)
            .map(|m| &m.claim)
    }

    /// The members, each with its name.
    pub fn members(&self) -> impl ExactSizeIterator<Item = (&str, &IssuedClaim)> + '_ {
        self.members.iter().map(|m| (m.name.as_str(), &m.claim))
    }

    /// The object as JSON, each withheld position an `{"...": digest}` element.
    pub(crate) fn node(&self) -> Result<Node<'static>, JsonError> {
        Node::object(
            self.members
                .iter()
                .map(|m| Ok((Cow::Owned(m.name.clone()), m.claim.value.node()?)))
                .collect::<Result<Vec<_>, JsonError>>()?,
        )
    }
}

/// An object member or an array element present in the issued credential.
pub struct IssuedClaim {
    value: ClaimValue,
    disclosure: Option<Disclosure>,
}

impl IssuedClaim {
    pub(crate) fn new(value: ClaimValue, disclosure: Option<Disclosure>) -> Self {
        Self { value, disclosure }
    }

    /// The value, with its nested disclosures processed.
    #[must_use]
    pub fn value(&self) -> &ClaimValue {
        &self.value
    }

    /// The disclosure that reveals the claim. `None` for a permanently disclosed claim.
    #[must_use]
    pub fn disclosure(&self) -> Option<&Disclosure> {
        self.disclosure.as_ref()
    }
}

/// A claim value of the processed payload.
pub enum ClaimValue {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, as written.
    Number(Number<'static>),
    /// A string.
    String(String),
    /// An array, at its issued length.
    Array(Vec<Element>),
    /// An object.
    Object(Object),
}

impl ClaimValue {
    fn node(&self) -> Result<Node<'static>, JsonError> {
        Ok(match self {
            Self::Null => Node::Null,
            Self::Bool(value) => Node::Bool(*value),
            Self::Number(number) => Node::Number(number.clone()),
            Self::String(text) => Node::String(Cow::Owned(text.clone())),
            Self::Array(elements) => Node::Array(
                elements
                    .iter()
                    .map(|element| match element {
                        Element::Present(claim) => claim.value.node(),
                        Element::Withheld(digest) => Node::object([(
                            Cow::Borrowed(ELLIPSIS),
                            Node::String(Cow::Owned(digest.as_str().to_owned())),
                        )]),
                    })
                    .collect::<Result<_, _>>()?,
            ),
            Self::Object(object) => object.node()?,
        })
    }
}

/// An array position of the issued credential.
pub enum Element {
    /// A permanently disclosed element, or one whose disclosure the credential holds.
    Present(IssuedClaim),
    /// A digest whose disclosure the credential lacks: a decoy (RFC 9901 §4.2.5), or an element
    /// the issuer kept back.
    Withheld(Digest),
}

/// A disclosure of the issued credential, by its position among the compact form's disclosures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DisclosureId(usize);

impl DisclosureId {
    /// The disclosure at `position`.
    #[must_use]
    pub const fn new(position: usize) -> Self {
        Self(position)
    }
}

impl IntoArg for DisclosureId {
    type Kind = <usize as IntoArg>::Kind;

    fn arg(&self) -> <Self::Kind as Kind>::Of<'_> {
        self.0.arg()
    }
}

/// A disclosure as issued: its position and its base64url text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure {
    id: DisclosureId,
    encoded: String,
}

impl Disclosure {
    pub(crate) fn new(id: DisclosureId, encoded: String) -> Self {
        Self { id, encoded }
    }

    /// The disclosure's position among the compact form's disclosures.
    #[must_use]
    pub fn id(&self) -> DisclosureId {
        self.id
    }

    /// The base64url text.
    #[must_use]
    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}
