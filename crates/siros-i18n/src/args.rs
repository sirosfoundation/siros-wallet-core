//! A message's arguments, as one resolution reads them.

use std::fmt::Write as _;

use rustc_hash::FxHashMap;

use crate::message::Message;
use crate::normal::normal;

/// A message's arguments: each key as [`normal`] holds it, with its value's text.
pub(crate) struct Args(FxHashMap<String, String>);

impl Args {
    /// The arguments `message` gives.
    ///
    /// # Errors
    ///
    /// The first key given twice, or whose value's `Display` fails.
    pub(crate) fn of(message: &dyn Message) -> Result<Self, String> {
        let mut args: FxHashMap<String, String> = FxHashMap::default();
        let mut refused: Option<String> = None;
        message.args(&mut |key, value| {
            if refused.is_some() {
                return;
            }
            let key = normal(key).into_owned();
            let mut text = String::new();
            if args.contains_key(&key) || write!(text, "{value}").is_err() {
                refused = Some(key);
            } else {
                args.extend([(key, text)]);
            }
        });
        match refused {
            Some(key) => Err(key),
            None => Ok(Self(args)),
        }
    }

    /// The text of the argument `key`.
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
}
