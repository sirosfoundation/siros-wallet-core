//! A message's arguments, as one resolution reads them.

use std::any::{Any, TypeId};
use std::fmt::Write as _;

use rustc_hash::FxHashMap;

use crate::message::Message;

/// The arguments a message's wording names: each key with its value's text and type.
pub(crate) struct Args<'k>(FxHashMap<&'k str, Given>);

/// An argument: its value's `Display`, and the value's type.
struct Given {
    text: String,
    of: TypeId,
}

impl<'k> Args<'k> {
    /// The arguments `message` has under `keys`, each by its value's `Display` and type.
    ///
    /// # Errors
    ///
    /// The first key whose value's `Display` fails.
    pub(crate) fn of(
        message: &dyn Message,
        keys: impl IntoIterator<Item = &'k str>,
    ) -> Result<Self, &'k str> {
        let mut args: FxHashMap<&'k str, Given> = FxHashMap::default();
        for key in keys {
            if let Some(value) = message.arg(key) {
                let mut text = String::new();
                write!(text, "{value}").map_err(|_| key)?;
                let of = (value as &dyn Any).type_id();
                args.extend([(key, Given { text, of })]);
            }
        }
        Ok(Self(args))
    }

    /// The text of the argument `key`.
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(|given| given.text.as_str())
    }

    /// The type of the argument `key`'s value.
    pub(crate) fn type_of(&self, key: &str) -> Option<TypeId> {
        self.0.get(key).map(|given| given.of)
    }
}
