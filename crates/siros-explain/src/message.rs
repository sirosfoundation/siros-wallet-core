//! The contract and what its derive writes: identifiers, [`Explain`], and the declarations of
//! [`Messages`].

use std::fmt;

use crate::arg::{ArgKind, ArgName, Args, IntoArg, Kind, Names, Presence};

/// A message identifier, `<domain>.<id>`: two or more [`tokens`]. Stable across releases, unique
/// among an app's messages. [`checked!`](crate::checked) makes one when the crate builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId(&'static str);

impl MessageId {
    /// The identifier; `None` for a text of fewer than two tokens.
    #[must_use]
    pub const fn new(id: &'static str) -> Option<Self> {
        if tokens(id, 2) { Some(Self(id)) } else { None }
    }

    /// Its text.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

/// A domain: one or more [`tokens`] (`openid4vp`, `openid4vp.routing`). A crate module's
/// identity, and the prefix of its messages' identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Domain(&'static str);

impl Domain {
    /// The domain; `None` for a text that is no tokens.
    #[must_use]
    pub const fn new(domain: &'static str) -> Option<Self> {
        if tokens(domain, 1) {
            Some(Self(domain))
        } else {
            None
        }
    }

    /// Its text.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

/// Whether a text is at least `min` tokens separated by `.`, each a lowercase ASCII letter, then
/// lowercase letters, digits and underscores: the grammar of identifiers, domains and keys.
#[must_use]
pub const fn tokens(text: &str, min: usize) -> bool {
    let mut rest = text.as_bytes();
    let (mut count, mut start) = (1, true);
    while let [b, tail @ ..] = rest {
        let b = *b;
        if b == b'.' {
            if start {
                return false;
            }
            start = true;
            count += 1;
        } else if start {
            if !b.is_ascii_lowercase() {
                return false;
            }
            start = false;
        } else if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            return false;
        }
        rest = tail;
    }
    !start && count >= min
}

/// A message's identity and arguments: what the renderer formats when the text is displayed.
///
/// # Implementing
///
/// Derive it (`#[derive(Explain)]` with the type's `domain`), on an error beside thiserror's
/// `Error`, on a text type alone, which has no `Display`; or write it by hand: `id` is a
/// [`MessageId`] made with `checked!`, unique across the build (one test over every crate's
/// `Messages`); `args` gives each argument under its declared name and kind, and a secret cannot
/// be one. Every error type and text type of a wallet crate implements it.
pub trait Explain: fmt::Debug + Send + Sync {
    /// The message's identifier.
    fn id(&self) -> MessageId;
    /// The values the message names, in the type's field order, under its [`Names`].
    fn args(&self) -> Args<'_>;
}

/// An error that is a message: what a refusal or a cause carries, boxed, until a text is needed.
pub trait Explained: Explain + std::error::Error + 'static {}

impl<T: Explain + std::error::Error + 'static> Explained for T {}

impl<T: Explain + ?Sized> Explain for &T {
    fn id(&self) -> MessageId {
        (**self).id()
    }

    fn args(&self) -> Args<'_> {
        (**self).args()
    }
}

impl<T: Explain + ?Sized> Explain for Box<T> {
    fn id(&self) -> MessageId {
        (**self).id()
    }

    fn args(&self) -> Args<'_> {
        (**self).args()
    }
}

/// The messages a type declares; `#[derive(Explain)]` writes it. A transparent variant declares
/// its cause's messages.
pub trait Messages {
    /// Every message of the type.
    fn messages() -> Vec<Message>;
}

/// One message as its type declares it: its key in the module, its English template, and its
/// parameters under distinct names. Only [`Message::new`] makes one, from [`Names`], which refuse
/// a repeated name when the crate builds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    id: MessageId,
    text: Option<&'static str>,
    params: Vec<Param>,
}

impl Message {
    /// The message: each name with the kind of its value's type ([`ParamKind::of`]), in order.
    #[must_use]
    pub fn new<const N: usize>(
        id: MessageId,
        text: Option<&'static str>,
        names: Names<N>,
        kinds: [ParamKind; N],
    ) -> Self {
        let params = names.into_array().into_iter().zip(kinds);
        Self {
            id,
            text,
            params: params.map(|(name, kind)| Param { name, kind }).collect(),
        }
    }

    /// The identifier.
    #[must_use]
    pub const fn id(&self) -> MessageId {
        self.id
    }

    /// The English template: the `#[error("…")]` literal, when the variant has one.
    #[must_use]
    pub const fn text(&self) -> Option<&'static str> {
        self.text
    }

    /// The parameters, in field order.
    #[must_use]
    pub fn params(&self) -> &[Param] {
        &self.params
    }
}

/// A parameter a message declares: its name and its value's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Param {
    name: ArgName,
    kind: ParamKind,
}

impl Param {
    /// The name.
    #[must_use]
    pub const fn name(self) -> ArgName {
        self.name
    }

    /// The kind of value, and whether it may be absent.
    #[must_use]
    pub const fn kind(self) -> ParamKind {
        self.kind
    }
}

/// The kind of value a parameter takes and whether it may be absent: its value type's, read from
/// [`IntoArg::Kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParamKind {
    kind: ArgKind,
    presence: Presence,
}

impl ParamKind {
    /// The kind of a value of type `T`.
    #[must_use]
    pub const fn of<T: IntoArg + ?Sized>() -> Self {
        Self {
            kind: <T::Kind as Kind>::KIND,
            presence: <T::Kind as Kind>::PRESENCE,
        }
    }

    /// The kind of a parameter a converter declares for a defined module, whose arguments no type
    /// fixes.
    #[must_use]
    pub const fn new(kind: ArgKind, presence: Presence) -> Self {
        Self { kind, presence }
    }

    /// The kind.
    #[must_use]
    pub const fn kind(self) -> ArgKind {
        self.kind
    }

    /// Whether the value may be absent.
    #[must_use]
    pub const fn presence(self) -> Presence {
        self.presence
    }
}
