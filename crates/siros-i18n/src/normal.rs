//! MF2 compares names (spec/syntax.md "Names and Identifiers"), variant keys ("Key") and the value
//! a `:string` selector compares (spec/functions/string.md "Selection") in Unicode Normalization
//! Form C. With feature `nfc` a context holds each in NFC, and the keys of a message's arguments
//! with them; without it, as written. Text, a literal a placeholder formats, and an argument's
//! value stay as written in both.
//!
//! A build without `nfc` resolves a module to the texts a build with it resolves when NFC changes
//! none of the module's names, keys and selector literals: [`Hold::Written`] loads a module only
//! then. The spec allows checking for NFC in place of normalizing ("Names and Identifiers").

use std::borrow::Cow;

#[cfg(feature = "nfc")]
use unicode_normalization::UnicodeNormalization;

/// `text` as the build holds a name, a variant key, a selector literal or an argument's key: in
/// NFC with `nfc`, as written without it. Borrowed when held as written.
#[cfg(feature = "nfc")]
pub(crate) fn normal(text: &str) -> Cow<'_, str> {
    if unicode_normalization::is_nfc(text) {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(text.nfc().collect())
    }
}

/// `text` as the build holds a name, a variant key, a selector literal or an argument's key: in
/// NFC with `nfc`, as written without it. Borrowed when held as written.
#[cfg(not(feature = "nfc"))]
pub(crate) fn normal(text: &str) -> Cow<'_, str> {
    Cow::Borrowed(text)
}

/// How a load holds the names, variant keys and selector literals of its messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hold {
    /// As [`normal`] holds them.
    Normal,
    /// As written, each one [`normal`] changes refused: the load of a build without `nfc`.
    #[cfg(feature = "nfc")]
    Written,
}

impl Hold {
    /// `text` as the load holds it: borrowed when held as written.
    ///
    /// # Errors
    ///
    /// [`Unnormalized`] under [`Hold::Written`] for a text [`normal`] changes.
    pub(crate) fn hold(self, text: &str) -> Result<Cow<'_, str>, Unnormalized> {
        match (normal(text), self) {
            (held @ Cow::Borrowed(_), _) | (held, Self::Normal) => Ok(held),
            #[cfg(feature = "nfc")]
            (Cow::Owned(_), Self::Written) => Err(Unnormalized(text.to_owned())),
        }
    }

    /// Checks that the load holds `text`, which a selector compares in [`normal`]'s form.
    ///
    /// # Errors
    ///
    /// [`Unnormalized`] under [`Hold::Written`] for a text [`normal`] changes.
    pub(crate) fn check(
        self,
        #[cfg_attr(
            not(feature = "nfc"),
            expect(unused_variables, reason = "a build without `nfc` holds every text")
        )]
        text: &str,
    ) -> Result<(), Unnormalized> {
        match self {
            Self::Normal => Ok(()),
            #[cfg(feature = "nfc")]
            Self::Written => match normal(text) {
                Cow::Borrowed(_) => Ok(()),
                Cow::Owned(_) => Err(Unnormalized(text.to_owned())),
            },
        }
    }
}

/// A name, a variant key or a selector literal, as written, that [`Hold::Written`] refuses.
#[cfg(feature = "nfc")]
#[derive(Debug)]
pub(crate) struct Unnormalized(String);

/// A build without `nfc` refuses no name, key or literal: no value of this type exists.
#[cfg(not(feature = "nfc"))]
#[derive(Debug)]
pub(crate) enum Unnormalized {}

impl Unnormalized {
    /// The text as written.
    #[cfg(feature = "nfc")]
    pub(crate) fn written(self) -> String {
        self.0
    }

    /// The text as written.
    #[cfg(not(feature = "nfc"))]
    pub(crate) fn written(self) -> String {
        match self {}
    }
}
