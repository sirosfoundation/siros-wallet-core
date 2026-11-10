//! A message's arguments, as one resolution reads them.

use std::fmt::Write as _;

use crate::message::Message;
use crate::normal::normal;

/// A message's arguments: each key as [`normal`] holds it with its value's text, each key once.
pub(crate) struct Args(Vec<(String, String)>);

impl Args {
    /// The arguments `message` gives.
    ///
    /// # Errors
    ///
    /// The first key given twice, or whose value's `Display` fails.
    pub(crate) fn of(message: &dyn Message) -> Result<Self, String> {
        let mut args: Vec<(String, String)> = Vec::new();
        let mut refused: Option<String> = None;
        message.args(&mut |key, value| {
            if refused.is_some() {
                return;
            }
            let key = normal(key).into_owned();
            let mut text = String::new();
            if args.iter().any(|(given, _)| *given == key) || write!(text, "{value}").is_err() {
                refused = Some(key);
            } else {
                args.push((key, text));
            }
        });
        match refused {
            Some(key) => Err(key),
            None => Ok(Self(args)),
        }
    }

    /// The text of the argument `key`.
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(given, _)| given == key)
            .map(|(_, text)| text.as_str())
    }
}
