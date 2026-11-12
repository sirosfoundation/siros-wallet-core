//! A message's arguments, as one resolution reads them.

use std::fmt::Write as _;

use rustc_hash::FxHashMap;

use crate::message::Message;

/// The arguments a message's wording reads: each key with its value's text.
pub(crate) struct Args<'k>(FxHashMap<&'k str, String>);

impl<'k> Args<'k> {
    /// The arguments `message` has under `keys`, each by its value's `Display`.
    ///
    /// # Errors
    ///
    /// The first key whose value's `Display` fails.
    pub(crate) fn of(
        message: &dyn Message,
        keys: impl IntoIterator<Item = &'k str>,
    ) -> Result<Self, &'k str> {
        let mut args: FxHashMap<&'k str, String> = FxHashMap::default();
        for key in keys {
            if let Some(value) = message.arg(key) {
                let mut text = String::new();
                write!(text, "{value}").map_err(|_| key)?;
                args.extend([(key, text)]);
            }
        }
        Ok(Self(args))
    }

    /// The text of the argument `key`.
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
}
