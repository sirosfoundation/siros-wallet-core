//! The texts that depend on a request, and the messages they draw from. A registration's package
//! holds a module's compiled messages for such texts alone: each module declares them as one type
//! ([`DeclaredModule::Requested`]), and a [`RequestText`] is built only from a message of that type,
//! from a value, a name, a received text, or a defined module's message, which the package holds
//! whole. A request text built from another message does not compile.

use std::borrow::Cow;

use crate::keyed::{Entry, Keyed};
use crate::list::{AllOf, ListKind};
use crate::message::{Explain, Messages};
use crate::text::{DefinedKey, DefinedModule, ModuleId, Query, Text};
use crate::value::Value;

/// A module the wallet registers, with the messages texts that depend on a request draw from.
///
/// # Implementing
///
/// `ID` is the module's identity; `Requested` is the one type whose messages request texts draw
/// from, `()` for a module none draws from. A crate implements it for its module type, and the
/// registration's package holds `Requested`'s messages compiled.
pub trait DeclaredModule {
    /// The module's identity.
    const ID: ModuleId;
    /// The messages texts that depend on a request draw from.
    type Requested: Messages;
}

/// The messages of a module that texts depending on a request draw from: its module's
/// [`DeclaredModule::Requested`], one type per module.
///
/// # Implementing
///
/// A module's crate implements it for the type its module declares; the bound on `Module` refuses
/// a second type of the same module.
pub trait Requested: Explain {
    /// The module whose request messages these are.
    type Module: DeclaredModule<Requested = Self>;
}

impl Messages for () {
    fn messages() -> Vec<crate::Message> {
        Vec::new()
    }
}

/// A text that depends on a request: what a transaction's overlay shows. Only its constructors
/// make one, each from what a registration's package holds compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestText(Text);

impl RequestText {
    /// The text of a module's request message.
    pub fn of<T: Requested>(message: &T) -> Self {
        Self(Text::of(message))
    }

    /// A typed value.
    #[must_use]
    pub const fn value(value: Value) -> Self {
        Self(Text::Value(value))
    }

    /// A name the code fixes.
    #[must_use]
    pub const fn name(name: &'static str) -> Self {
        Self(Text::Name(name))
    }

    /// A text from the outside, shown as written.
    #[must_use]
    pub const fn raw(text: String) -> Self {
        Self(Text::Raw(text))
    }

    /// An optional value the input left out.
    #[must_use]
    pub const fn absent() -> Self {
        Self(Text::Absent)
    }

    /// A defined module's message, its arguments request texts.
    #[must_use]
    pub fn defined(
        module: DefinedModule,
        key: DefinedKey,
        args: Keyed<Cow<'static, str>, Self>,
    ) -> Self {
        let args = args
            .into_entries()
            .into_iter()
            .map(|entry| {
                let (name, text) = (entry.key().clone(), entry.into_value());
                Entry::new(name, text.0)
            })
            .collect::<Vec<_>>();
        Self(Text::Query(Query::defined(
            module,
            key,
            Keyed::first_of(args),
        )))
    }

    /// Texts shown one after another.
    #[must_use]
    pub fn joined(items: AllOf<Self>) -> Self {
        Self(Text::Joined(items.map(|item| item.0)))
    }

    /// Texts as a list.
    #[must_use]
    pub fn list(kind: ListKind, items: AllOf<Self>) -> Self {
        Self(Text::List {
            kind,
            items: items.map(|item| item.0),
        })
    }

    /// The text.
    #[must_use]
    pub const fn text(&self) -> &Text {
        &self.0
    }

    /// The text, taken.
    #[must_use]
    pub fn into_text(self) -> Text {
        self.0
    }
}

impl std::ops::Deref for RequestText {
    type Target = Text;

    fn deref(&self) -> &Text {
        &self.0
    }
}

impl From<RequestText> for Text {
    fn from(text: RequestText) -> Self {
        text.0
    }
}
