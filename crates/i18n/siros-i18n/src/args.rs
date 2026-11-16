//! A message's arguments, as one resolution reads them.

use std::any::{Any, TypeId};
use std::fmt::Write as _;

use rustc_hash::FxHashMap;
use siros_explain::Arg;

use crate::message::Message;

/// The arguments a message's wording names: each key with its value and the value's text.
pub(crate) struct Args<'k>(FxHashMap<&'k str, Given<'k>>);

/// An argument: its value, and the value's `Display`.
struct Given<'k> {
    value: &'k dyn Arg,
    text: String,
}

impl<'k> Args<'k> {
    /// The arguments `message` has under `keys`, each with its value's `Display`.
    ///
    /// # Errors
    ///
    /// The first key whose value's `Display` fails.
    pub(crate) fn of(
        message: &'k dyn Message,
        keys: impl IntoIterator<Item = &'k str>,
    ) -> Result<Self, &'k str> {
        let mut args: FxHashMap<&'k str, Given<'k>> = FxHashMap::default();
        for key in keys {
            if let Some(value) = message.arg(key) {
                let mut text = String::new();
                write!(text, "{value}").map_err(|_| key)?;
                args.extend([(key, Given { value, text })]);
            }
        }
        Ok(Self(args))
    }

    /// The text of the argument `key`.
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(|given| given.text.as_str())
    }

    /// The value of the argument `key`.
    pub(crate) fn value(&self, key: &str) -> Option<&'k dyn Arg> {
        self.0.get(key).map(|given| given.value)
    }

    /// The type of the argument `key`'s value.
    pub(crate) fn type_of(&self, key: &str) -> Option<TypeId> {
        self.0.get(key).map(|given| (given.value as &dyn Any).type_id())
    }
}
