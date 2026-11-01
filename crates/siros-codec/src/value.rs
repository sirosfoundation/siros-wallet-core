//! The macros that declare value newtypes, a position in a list and a text whose role is its
//! type, and the macro that shows an error by its stable code.

/// Declares a position among the items of one list: a number, from 0. The visibility before
/// the name is the constructor's: `pub(crate)` for a position the crate takes as it enumerates
/// the list, `pub` for one a caller names.
#[macro_export]
macro_rules! position {
    ($(#[$doc:meta])* $new:vis $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(usize);

        impl $name {
            /// The position `value`.
            #[must_use]
            $new const fn new(value: usize) -> Self {
                Self(value)
            }

            /// The position, from 0.
            #[must_use]
            pub const fn value(self) -> usize {
                self.0
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::write!(f, "{}", self.0)
            }
        }
    };
}

/// Declares a text of any content whose role is its type. A constant is a `from_static`.
#[macro_export]
macro_rules! text_value {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(::std::borrow::Cow<'static, str>);

        impl $name {
            /// The value `text`.
            #[must_use]
            pub fn new(text: &str) -> Self {
                Self(::std::borrow::Cow::Owned(text.to_owned()))
            }

            /// The value `text`, a constant.
            #[must_use]
            pub const fn from_static(text: &'static str) -> Self {
                Self(::std::borrow::Cow::Borrowed(text))
            }

            /// The value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl ::core::cmp::PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl ::core::cmp::PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }

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
