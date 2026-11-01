//! The processed claims of a stored SD-JWT, each node with the disclosure that reveals it.
//!
//! An array keeps its issued positions (SD-JWT VC, Section 9.1.2: a path addresses a claim "as
//! if all selectively disclosable claims were disclosed"). An array digest without a
//! disclosure, a decoy among them, is an [`Element::Withheld`] at its position.

use serde_json::Number;
use siros_codec::base64url::Base64Url;

/// A JSON object of the processed payload.
///
/// Its permanently disclosed members come first, in issued order, then the members its
/// disclosures add, in the order of its `_sd` digests.
pub struct Object {
    members: Vec<Member>,
}

struct Member {
    name: String,
    claim: Claim,
}

impl Object {
    pub(crate) fn new() -> Self {
        Self {
            members: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, name: String, claim: Claim) {
        self.members.push(Member { name, claim });
    }

    /// The member named `name`.
    pub fn get(&self, name: &str) -> Option<&Claim> {
        self.members
            .iter()
            .find(|m| m.name == name)
            .map(|m| &m.claim)
    }

    /// The members, each with its name.
    pub fn members(&self) -> impl ExactSizeIterator<Item = (&str, &Claim)> + '_ {
        self.members.iter().map(|m| (m.name.as_str(), &m.claim))
    }
}

/// An object member or an array element present in the stored credential.
pub struct Claim {
    value: ClaimValue,
    disclosure: Option<Disclosure>,
}

impl Claim {
    pub(crate) fn new(value: ClaimValue, disclosure: Option<Disclosure>) -> Self {
        Self { value, disclosure }
    }

    /// The value, with its nested disclosures processed.
    pub fn value(&self) -> &ClaimValue {
        &self.value
    }

    /// The disclosure that reveals the claim. `None` for a permanently disclosed claim.
    pub fn disclosure(&self) -> Option<DisclosureId> {
        self.disclosure.as_ref().map(|d| d.id)
    }

    pub(crate) fn disclosure_text(&self) -> Option<&str> {
        self.disclosure.as_ref().map(|d| d.encoded.as_str())
    }
}

/// A claim value of the processed payload.
pub enum ClaimValue {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number.
    Number(Number),
    /// A string.
    String(String),
    /// An array, at its issued length.
    Array(Vec<Element>),
    /// An object.
    Object(Object),
}

/// An array position of the issued credential.
pub enum Element {
    /// A permanently disclosed element, or one whose disclosure the credential holds.
    Present(Claim),
    /// A digest whose disclosure the credential lacks: a decoy (RFC 9901, Section 4.2.5), or an
    /// element the issuer kept back.
    Withheld,
}

siros_codec::position!(
    /// A disclosure of the stored credential, named by its position among the disclosures of
    /// the compact form.
    pub DisclosureId
);

/// A disclosure as stored: its position and its base64url text.
pub(crate) struct Disclosure {
    id: DisclosureId,
    encoded: Base64Url,
}

impl Disclosure {
    pub(crate) fn new(id: DisclosureId, encoded: Base64Url) -> Self {
        Self { id, encoded }
    }

    pub(crate) fn id(&self) -> DisclosureId {
        self.id
    }
}
