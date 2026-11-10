//! The identifiers and protocol strings the request, the registration and the plug-ins share.
//! Each is constructed only by parsing, so holding one means its rule held.

use std::borrow::Cow;
use std::fmt;

use siros_explain::Explain;

/// A language tag of the End-User's priority list, and a text that is none.
pub use siros_i18n::{InvalidTag, LocaleTag};

/// A string that breaks the rule of the identifier it was parsed as.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(id = "invalid_id")]
#[error("{value:?} is no {what}")]
pub struct InvalidId {
    /// What the string was parsed as.
    pub what: &'static str,
    /// The string.
    pub value: String,
}

macro_rules! text_id {
    ($(#[$doc:meta])* $name:ident, $what:literal, $rule:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name<'a>(Cow<'a, str>);

        impl<'a> $name<'a> {
            /// Parses the identifier.
            pub fn parse(text: impl Into<Cow<'a, str>>) -> Result<Self, InvalidId> {
                let text = text.into();
                let rule: fn(&str) -> bool = $rule;
                if rule(&text) {
                    Ok(Self(text))
                } else {
                    Err(InvalidId { what: $what, value: text.into_owned() })
                }
            }

            /// The identifier's text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// The identifier, borrowing its text.
            #[must_use]
            pub fn borrowed(&self) -> $name<'_> {
                $name(Cow::Borrowed(&self.0))
            }

            /// The identifier, owning its text.
            #[must_use]
            pub fn into_owned(self) -> $name<'static> {
                $name(Cow::Owned(self.0.into_owned()))
            }
        }

        impl AsRef<str> for $name<'_> {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl PartialEq<str> for $name<'_> {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }
    };
}

fn non_empty(text: &str) -> bool {
    !text.is_empty()
}

/// OpenID4VP §6.1 and §6.3's identifier rule: non-empty, of ASCII letters, digits, `_` and `-`.
fn dcql_id(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

text_id!(
    /// A Credential Query identifier (OpenID4VP §6.1): non-empty, of ASCII letters, digits,
    /// `_` and `-`.
    QueryId,
    "Credential Query id",
    dcql_id
);
text_id!(
    /// A claims query identifier (OpenID4VP §6.3): non-empty, of ASCII letters, digits, `_` and
    /// `-`.
    ClaimId,
    "claims query id",
    dcql_id
);
text_id!(
    /// A Credential Format Identifier (OpenID4VP Appendix B), selecting the format plug-in.
    FormatId,
    "Credential Format Identifier",
    non_empty
);
text_id!(
    /// A `credential_ids` element as a `transaction_data` entry wrote it (OpenID4VP §5.1): the
    /// text rule C2 looks up among the Credential Query identifiers.
    NamedQueryId,
    "credential_ids element",
    |_| true
);
text_id!(
    /// An `expected_origins` element as a signed request wrote it (OpenID4VP Annex A): the text
    /// rule C8 compares with the [`Origin`].
    ExpectedOrigin,
    "expected_origins element",
    |_| true
);
text_id!(
    /// The `response_uri` as the request wrote it, which authentication parses (A13) into a
    /// `ResponseUri`.
    NamedResponseUri,
    "response_uri",
    |_| true
);
text_id!(
    /// A wallet's static consent entry's id, which the platform returns when the End-User picks
    /// it.
    StaticEntryId,
    "static entry id",
    non_empty
);
text_id!(
    /// A key's `kid` (RFC 7517 §4.5; in a JOSE header, RFC 7515 §4.1.4): a case-sensitive string.
    KeyId,
    "kid",
    |_| true
);
text_id!(
    /// A credential's type as its format reads it from the view: a `vct` (SD-JWT VC §3.2.2.2) or
    /// a docType (ISO/IEC 18013-5 §7.1).
    CredentialType,
    "credential type",
    |_| true
);
text_id!(
    /// The wallet's identifier of a credential it registered.
    CredentialId,
    "credential id",
    non_empty
);
text_id!(
    /// A transaction data type identifier (OpenID4VP §5.1 `transaction_data` `type`): any string.
    TransactionType,
    "transaction data type",
    |_| true
);
text_id!(
    /// The Origin the platform reports for a DC API request (OpenID4VP Annex A), as the
    /// platform serializes it.
    Origin,
    "Origin",
    non_empty
);
text_id!(
    /// The `nonce` request parameter (OpenID4VP §5.2): non-empty URL-safe ASCII, letters,
    /// digits, `-`, `.`, `_` and `~` (N1).
    Nonce,
    "nonce",
    |text| {
        !text.is_empty()
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    }
);
text_id!(
    /// A Client Identifier with its Client Identifier Prefix (OpenID4VP §5.9): one or more of RFC
    /// 6749 Appendix A.1's `VSCHAR`, %x20-7E (U3).
    ClientId,
    "Client Identifier",
    |text| !text.is_empty() && text.bytes().all(|b| (0x20..=0x7e).contains(&b))
);
text_id!(
    /// The key a plug-in's document carries in a credential's registration.
    DocumentKey,
    "document key",
    non_empty
);
text_id!(
    /// A Trusted Authorities Query `type` (OpenID4VP §6.1.1).
    AuthorityType,
    "trusted authority type",
    |_| true
);
text_id!(
    /// One value of a Trusted Authorities Query, or one the wallet resolved for a credential.
    AuthorityValue,
    "trusted authority value",
    |_| true
);
text_id!(
    /// A transaction data type prefix a profile is registered under.
    TypePrefix,
    "transaction data type prefix",
    non_empty
);
impl DocumentKey<'static> {
    /// The key; `None` for an empty text. A plug-in names its own with `checked!(DocumentKey,
    /// "...")`.
    #[must_use]
    pub const fn new(key: &'static str) -> Option<Self> {
        if key.is_empty() {
            None
        } else {
            Some(Self(Cow::Borrowed(key)))
        }
    }
}
impl TypePrefix<'static> {
    /// The prefix; `None` for an empty text. A profile names its own with `checked!(TypePrefix,
    /// "...")`.
    #[must_use]
    pub const fn new(prefix: &'static str) -> Option<Self> {
        if prefix.is_empty() {
            None
        } else {
            Some(Self(Cow::Borrowed(prefix)))
        }
    }
}
impl<'a> AuthorityType<'a> {
    /// The type `text`: §6.1.1 sets no rule on its form.
    pub fn of(text: impl Into<Cow<'a, str>>) -> Self {
        Self(text.into())
    }
}
impl<'a> AuthorityValue<'a> {
    /// The value `text`: §6.1.1 sets each type's values, and an unknown form equals no held value.
    pub fn of(text: impl Into<Cow<'a, str>>) -> Self {
        Self(text.into())
    }
}
/// A Credential Format Identifier a claims format names itself by, as its refusals name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FormatName(&'static str);

impl FormatName {
    /// The name; `None` for an empty text. A format names its own with `checked!(FormatName,
    /// "...")`.
    #[must_use]
    pub const fn new(name: &'static str) -> Option<Self> {
        if name.is_empty() {
            None
        } else {
            Some(Self(name))
        }
    }

    /// The text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for FormatName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl ClientId<'_> {
    /// The Client Identifier Prefix and the original identifier (§5.9.1): the text before the
    /// first `:` and the text after it; `None` for an identifier without a `:`, a pre-registered
    /// client's (§5.9.2).
    #[must_use]
    pub fn prefixed(&self) -> Option<(&str, &str)> {
        self.0.split_once(':')
    }
}
impl TransactionType<'_> {
    /// Whether the type identifier starts with the prefix.
    #[must_use]
    pub fn has_prefix(&self, prefix: &TypePrefix<'_>) -> bool {
        self.0.starts_with(prefix.as_str())
    }
}
