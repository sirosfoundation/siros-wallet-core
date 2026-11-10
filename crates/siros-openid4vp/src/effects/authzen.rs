//! Trust questions in the shape of AuthZEN Authorization API 1.0 access evaluations (§5:
//! subject, action, resource, context; decision; §6.1): the prefix plug-in chooses the type
//! strings and reads the answers. JSON objects are the core's, whose names are unique at every
//! level.

use super::Reply;
use crate::json::Object;

/// An AuthZEN entity's `type` (§5.1, §5.2): non-empty, fixed by the plug-in that asks, which
/// makes its own with `siros_syntax::checked!`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntityType(&'static str);

impl EntityType {
    /// The type; `None` for an empty text.
    #[must_use]
    pub const fn new(kind: &'static str) -> Option<Self> {
        if kind.is_empty() {
            None
        } else {
            Some(Self(kind))
        }
    }

    /// Its text.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

/// An AuthZEN entity's `id` (§5.1, §5.2): a non-empty string, scoped to the entity's type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityId(String);

impl EntityId {
    /// The id; `None` for an empty text.
    #[must_use]
    pub fn parse(id: String) -> Option<Self> {
        (!id.is_empty()).then_some(Self(id))
    }

    /// Its text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl EntityId {
    /// The id of a SHA-256 digest: its base64url text without padding, 43 characters.
    #[must_use]
    pub fn digest(octets: &[u8; 32]) -> Self {
        use base64::Engine;
        Self(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(octets))
    }
}

/// An Origin is a non-empty id.
impl From<&crate::ids::Origin<'_>> for EntityId {
    fn from(origin: &crate::ids::Origin<'_>) -> Self {
        Self(origin.to_string())
    }
}

/// A Client Identifier is a non-empty id.
impl From<&crate::ids::ClientId<'_>> for EntityId {
    fn from(client_id: &crate::ids::ClientId<'_>) -> Self {
        Self(client_id.to_string())
    }
}

/// An AuthZEN subject or resource (§5.1, §5.2): a type, an id scoped to it, and properties.
#[derive(Debug, Clone)]
pub struct Entity {
    /// `type`.
    pub kind: EntityType,
    /// `id`.
    pub id: EntityId,
    /// `properties`.
    pub properties: Option<Object<'static>>,
}

/// An AuthZEN action's `name` (§5.3): non-empty, fixed by the plug-in that asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActionName(&'static str);

impl ActionName {
    /// The name; `None` for an empty text.
    #[must_use]
    pub const fn new(name: &'static str) -> Option<Self> {
        if name.is_empty() {
            None
        } else {
            Some(Self(name))
        }
    }

    /// Its text.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

/// An AuthZEN action (§5.3): a name and properties.
#[derive(Debug, Clone)]
pub struct Action {
    /// `name`.
    pub name: ActionName,
    /// `properties`.
    pub properties: Option<Object<'static>>,
}

/// An AuthZEN access evaluation request (§6.1): may the subject perform the action on the
/// resource, in the context? It takes a [`Decision`].
#[derive(Debug, Clone)]
pub struct Evaluation {
    /// The subject: the Verifier as identified.
    pub subject: Entity,
    /// The action.
    pub action: Action,
    /// The resource: what binds the subject, such as a certificate chain.
    pub resource: Entity,
    /// The context: the channel, the Origin, the endpoints.
    pub context: Option<Object<'static>>,
}

/// The caller's verdict (AuthZEN §5.5: `decision` true or false).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// `true`.
    Permit,
    /// `false`: the access is denied and goes no further (§5.5).
    Deny,
}

/// The caller's answer to an evaluation: the verdict and the decision's context (AuthZEN §5.5,
/// §5.5.1).
#[derive(Debug, Clone)]
pub struct Decision {
    /// The verdict.
    pub verdict: Verdict,
    /// The context the plug-in reads: the endpoints the framework registers, the facts it states.
    pub context: Option<Object<'static>>,
}

/// The decisions on one prefix claim's evaluations, in the order it asked them: its share of the
/// step's filled slots. Only `Pending::authenticate` makes one.
#[derive(Debug, Clone, Copy)]
pub struct Decided<'a>(&'a [Reply<Evaluation>]);

impl<'a> Decided<'a> {
    #[cfg(feature = "signed")]
    pub(crate) const fn of(replies: &'a [Reply<Evaluation>]) -> Self {
        Self(replies)
    }

    /// Each evaluation with its decision, in the order the claim asked them.
    #[must_use]
    pub const fn replies(&self) -> &'a [Reply<Evaluation>] {
        self.0
    }
}
