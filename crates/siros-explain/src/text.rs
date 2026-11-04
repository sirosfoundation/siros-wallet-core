//! Texts held unrendered: what a box, a row, a record and the matcher's pick store.

use std::borrow::Cow;

use crate::arg::ArgValue;
use crate::keyed::{Entry, Keyed};
use crate::list::{AllOf, ListKind};
use crate::message::{Domain, Explain, MessageId, tokens};
use crate::value::Value;

/// A text the End-User may see, unrendered and held by value: what a box, a row, a record and the
/// matcher's pick store. Taking one copies the arguments and formats nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Text {
    /// An i18n query: a module's message and its arguments.
    Query(Query),
    /// A typed value.
    Value(Value),
    /// A name the code fixes, shown as code.
    Name(&'static str),
    /// Several texts, one or more, as an and-list or an or-list, formatted with its module's
    /// format options, or the main module's when it stands alone.
    List {
        /// The list it forms.
        kind: ListKind,
        /// The texts.
        items: AllOf<Text>,
    },
    /// An optional value the input left out.
    Absent,
    /// A text from the outside, shown as written: the last resort.
    Raw(String),
}

/// An i18n query held by value: a module's message and its arguments, under distinct names.
/// [`Query::of`] and [`Query::defined`] make one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    key: Key,
    args: Keyed<Cow<'static, str>, Text>,
}

/// Which message a query names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    /// A crate module's message.
    Message(MessageId),
    /// A defined module's message: the module and the key its converter gave.
    Defined {
        /// The module.
        module: DefinedModule,
        /// The key.
        key: DefinedKey,
    },
}

/// A defined module's key, as its converter gives it: one or more [`tokens`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DefinedKey(String);

impl DefinedKey {
    /// The key; `None` for a text that is no tokens.
    #[must_use]
    pub fn parse(key: String) -> Option<Self> {
        tokens(&key, 1).then_some(Self(key))
    }

    /// Its text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A module's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModuleId {
    /// The wallet's main module: its own texts, in the languages the wallet supports.
    Main,
    /// A crate's messages, under its domain.
    Crate(Domain),
    /// Display rules converted from metadata.
    Defined(DefinedModule),
}

/// A defined module's identity: the plug-in that converted the metadata's display rules, by its
/// domain, and the metadata's SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DefinedModule {
    plugin: Domain,
    digest: [u8; 32],
}

impl DefinedModule {
    /// The module `plugin` converted from the metadata of SHA-256 `digest`.
    #[must_use]
    pub const fn new(plugin: Domain, digest: [u8; 32]) -> Self {
        Self { plugin, digest }
    }

    /// The converting plug-in's domain.
    #[must_use]
    pub const fn plugin(self) -> Domain {
        self.plugin
    }

    /// The metadata's SHA-256.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

impl Text {
    /// The text of a message.
    pub fn of(message: &dyn Explain) -> Self {
        Self::Query(Query::of(message))
    }

    fn held(arg: ArgValue<'_>) -> Self {
        match arg {
            ArgValue::Message(message) => Self::of(message),
            ArgValue::Value(value) => Self::Value(value),
            ArgValue::Name(name) => Self::Name(name),
            ArgValue::List { kind, items } => Self::List {
                kind,
                items: items.map(|item| Self::held(item.into_value())),
            },
            ArgValue::Absent => Self::Absent,
            ArgValue::Held(text) => text.clone(),
            ArgValue::Raw(text) => Self::Raw(text.to_owned()),
        }
    }
}

impl Query {
    /// The query of a message: its arguments under their [`Names`](crate::Names).
    pub fn of(message: &dyn Explain) -> Self {
        let args = message.args().into_vec().into_iter();
        let args = args.map(|named| {
            Entry::new(
                Cow::Borrowed(named.name.as_str()),
                Text::held(named.arg.into_value()),
            )
        });
        Self {
            key: Key::Message(message.id()),
            args: Keyed::distinct(args.collect()),
        }
    }

    /// The query of a defined module's message, as its converter writes it.
    #[must_use]
    pub fn defined(
        module: DefinedModule,
        key: DefinedKey,
        args: Keyed<Cow<'static, str>, Text>,
    ) -> Self {
        Self {
            key: Key::Defined { module, key },
            args,
        }
    }

    /// The message.
    #[must_use]
    pub const fn key(&self) -> &Key {
        &self.key
    }

    /// The arguments, by name, in their order.
    #[must_use]
    pub fn args(&self) -> &[Entry<Cow<'static, str>, Text>] {
        self.args.entries()
    }
}
