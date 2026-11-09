//! Values a type's rule admits, made when the crate builds.

/// A value of a type whose `const fn new(&'static str) -> Option<Self>` holds its rule, made when
/// the crate builds: a text the rule refuses fails the build (E0080). The evaluation is the
/// compiler's, so nothing runs at run time.
///
/// ```
/// use siros_syntax::checked;
///
/// /// A text of lowercase ASCII letters.
/// struct Lower(&'static str);
///
/// impl Lower {
///     const fn new(text: &'static str) -> Option<Self> {
///         let mut rest = text.as_bytes();
///         while let [first, tail @ ..] = rest {
///             if !first.is_ascii_lowercase() {
///                 return None;
///             }
///             rest = tail;
///         }
///         Some(Self(text))
///     }
/// }
///
/// const CANCELLED: Lower = checked!(Lower, "cancelled");
/// assert_eq!(CANCELLED.0, "cancelled");
/// ```
#[macro_export]
macro_rules! checked {
    ($type:ty, $text:literal) => {
        const {
            #[allow(
                clippy::expect_used,
                reason = "a panic in a constant fails the build (E0080)"
            )]
            let value = <$type>::new($text).expect(::core::concat!(
                ::core::stringify!($type),
                " refuses ",
                $text
            ));
            value
        }
    };
}
