//! The text values a Credential Query's `format` and `meta` name (§6.1; OpenID4VP 1.0,
//! Appendix B), and the wallet's reference to a credential it holds.

/// Declares a text value of any content whose role is its type.
macro_rules! text_value {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, ::serde::Serialize, ::serde::Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// The value `text`.
            #[must_use]
            pub fn new(text: &str) -> Self {
                Self(text.to_owned())
            }

            /// The value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<&str> for $name {
            fn from(text: &str) -> Self {
                Self::new(text)
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

        /// Map lookups by the text.
        impl ::core::borrow::Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

pub(crate) use text_value;

text_value!(
    /// A Credential Format Identifier (§6.1 `format`), such as `mso_mdoc` or `dc+sd-jwt`
    /// (OpenID4VP 1.0, Appendix B).
    CredentialFormat
);

text_value!(
    /// The wallet's identifier of a credential it holds, which match results echo.
    CredentialRef
);

text_value!(
    /// An mdoc `docType` (ISO/IEC 18013-5), as `meta.doctype_value` names it (OpenID4VP 1.0,
    /// B.2.3).
    DocType
);

text_value!(
    /// An SD-JWT VC type `vct`, as `meta.vct_values` names it (OpenID4VP 1.0, B.3.5).
    Vct
);
