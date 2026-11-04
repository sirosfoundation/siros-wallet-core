//! Values a type's rule admits, made when the crate builds.

/// A value of a type whose `const fn new(&'static str) -> Option<Self>` holds its rule, made when
/// the crate builds: a text the rule refuses fails the build (E0080). The evaluation is the
/// compiler's, so nothing runs at run time.
///
/// ```
/// use siros_explain::{checked, MessageId};
///
/// const CANCELLED: MessageId = checked!(MessageId, "openid4vp.host.cancelled");
/// assert_eq!(CANCELLED.as_str(), "openid4vp.host.cancelled");
/// ```
///
/// An identifier outside the grammar does not build:
///
/// ```compile_fail,E0080
/// use siros_explain::{checked, MessageId};
///
/// const BAD: MessageId = checked!(MessageId, "openid4vp.Host");
/// ```
#[macro_export]
macro_rules! checked {
    ($type:ty, $text:literal) => {
        const {
            match <$type>::new($text) {
                ::core::option::Option::Some(value) => value,
                #[allow(
                    clippy::panic,
                    reason = "a panic in a constant fails the build (E0080)"
                )]
                ::core::option::Option::None => {
                    ::core::panic!(::core::concat!(
                        ::core::stringify!($type),
                        " refuses ",
                        $text
                    ))
                }
            }
        }
    };
}
