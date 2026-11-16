//! Credential Query and claims query identifiers (§6.1, §6.3).

use core::fmt;
use core::ops::Deref;

use serde::{Deserialize, Serialize};

/// Declares an identifier of §6.1 or §6.3, with its error: "a non-empty string consisting of
/// alphanumeric, underscore (`_`), or hyphen (`-`) characters", alphanumeric read as ASCII.
macro_rules! identifier {
    (
        $(#[$doc:meta])*
        $name:ident,
        $(#[$error_doc:meta])*
        $error:ident,
        $what:literal,
        $empty:literal,
        $character:literal
    ) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        $(#[$error_doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
        #[error("{}", self.code())]
        pub enum $error {
            /// The text is empty.
            Empty,
            /// The text holds this character, outside ASCII letters, digits, `_` and `-`.
            Character(char),
        }

        impl $error {
            /// A stable identifier.
            #[must_use]
            pub fn code(self) -> &'static str {
                match self {
                    Self::Empty => $empty,
                    Self::Character(_) => $character,
                }
            }
        }

        impl $name {
            #[doc = concat!("The ", $what, " `text`.")]
            ///
            /// # Errors
            ///
            #[doc = concat!("[`", stringify!($error), "`]: an empty text, or one with another character.")]
            pub fn parse(text: &str) -> Result<Self, $error> {
                match foreign_character(text) {
                    Some(c) => Err($error::Character(c)),
                    None if text.is_empty() => Err($error::Empty),
                    None => Ok(Self(text.to_owned())),
                }
            }

            /// The identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = $error;

            fn try_from(text: String) -> Result<Self, $error> {
                Self::parse(&text)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl Deref for $name {
            type Target = str;

            fn deref(&self) -> &str {
                &self.0
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<String> for $name {
            fn eq(&self, other: &String) -> bool {
                &self.0 == other
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

/// The first character of `text` outside the identifier alphabet of §6.1 and §6.3: ASCII
/// letters, digits, `_` and `-`. One function for every identifier type, so that
/// `matcher.wasm` holds its code once.
#[inline(never)]
fn foreign_character(text: &str) -> Option<char> {
    text.chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-'))
}

identifier!(
    /// A Credential Query `id` (§6.1). The response keys the presentations by it, and
    /// `credential_sets` names queries by it.
    QueryId,
    /// Why a text is no Credential Query `id`.
    QueryIdError,
    "a credential query id",
    "query_id_empty",
    "query_id_character"
);

identifier!(
    /// A claims query `id` (§6.3). `claim_sets` names claims by it.
    ClaimId,
    /// Why a text is no claims query `id`.
    ClaimIdError,
    "a claims query id",
    "claim_id_empty",
    "claim_id_character"
);
