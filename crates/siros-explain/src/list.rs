//! Lists a message names: one or more values.

use crate::arg::{Arg, ArgValue, IntoArg};
use crate::kind;

/// The list a [`Text::List`](crate::Text::List) or an [`ArgValue::List`](crate::ArgValue::List)
/// forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListKind {
    /// An and-list.
    And,
    /// An or-list.
    Or,
}

/// What a value of [`kind::List`] gives: the list it forms and its arguments, one or more.
#[derive(Debug, Clone)]
pub struct Listed<'a> {
    kind: ListKind,
    items: AllOf<Arg<'a>>,
}

impl<'a> Listed<'a> {
    /// The arguments, as a list of `kind`.
    #[must_use]
    pub const fn new(kind: ListKind, items: AllOf<Arg<'a>>) -> Self {
        Self { kind, items }
    }

    /// The list as an argument.
    pub(crate) fn into_arg(self) -> Arg<'a> {
        Arg::held(ArgValue::List {
            kind: self.kind,
            items: self.items,
        })
    }
}

/// A list a message names: one or more values, in the order given. `new` refuses an empty list,
/// so a message never names an empty list.
macro_rules! list {
    ($(#[$doc:meta])* $name:ident, $kind:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name<T>(Vec<T>);

        impl<T> $name<T> {
            /// The values, in their order; `None` for no value.
            #[must_use]
            pub fn new(items: Vec<T>) -> Option<Self> {
                (!items.is_empty()).then_some(Self(items))
            }

            /// One value.
            #[must_use]
            pub fn one(item: T) -> Self {
                Self(vec![item])
            }

            /// The values, in their order.
            #[must_use]
            pub fn items(&self) -> &[T] {
                &self.0
            }

            /// The values, by value.
            #[must_use]
            pub fn into_items(self) -> Vec<T> {
                self.0
            }

            /// Each value mapped, in the same order.
            #[must_use]
            pub fn map<U>(self, f: impl FnMut(T) -> U) -> $name<U> {
                $name(self.0.into_iter().map(f).collect())
            }

            /// Each value mapped, in the same order; the first error when a value fails.
            ///
            /// # Errors
            ///
            /// The first error `f` returns.
            pub fn try_map<U, E>(
                &self,
                f: impl FnMut(&T) -> Result<U, E>,
            ) -> Result<$name<U>, E> {
                self.0.iter().map(f).collect::<Result<_, _>>().map($name)
            }

            /// These values, then `later`'s.
            #[must_use]
            pub fn and(mut self, later: Self) -> Self {
                self.0.extend(later.0);
                self
            }
        }

        impl<T: IntoArg> IntoArg for $name<T> {
            type Kind = kind::List;

            fn arg(&self) -> Listed<'_> {
                Listed::new($kind, AllOf(self.0.iter().map(Arg::of).collect()))
            }
        }
    };
}

list!(
    /// Values a message names as an and-list: one or more.
    AllOf,
    ListKind::And
);
list!(
    /// Values a message names as an or-list: one or more.
    AnyOf,
    ListKind::Or
);
