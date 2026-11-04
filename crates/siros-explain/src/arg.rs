//! A message's arguments: their names, their values, and the kinds their types declare.

use crate::list::{AllOf, ListKind};
use crate::message::{Explain, tokens};
use crate::text::Text;
use crate::value::Value;

/// An argument's name in a message: one or more [`tokens`] (`at`, `fn_id`). [`Names`] holds a
/// message's names, each once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArgName(&'static str);

impl ArgName {
    /// The name; `None` for a text that is no tokens.
    #[must_use]
    pub const fn new(name: &'static str) -> Option<Self> {
        if tokens(name, 1) {
            Some(Self(name))
        } else {
            None
        }
    }

    /// Its text.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

/// Whether two texts are equal, byte for byte, in a constant context.
const fn same(a: &str, b: &str) -> bool {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    loop {
        match (a, b) {
            ([], []) => return true,
            ([x, a_tail @ ..], [y, b_tail @ ..]) if *x == *y => {
                a = a_tail;
                b = b_tail;
            }
            _ => return false,
        }
    }
}

/// Whether `name` is among `names`, in a constant context.
const fn among(name: &str, mut names: &[&str]) -> bool {
    while let [first, tail @ ..] = names {
        if same(name, first) {
            return true;
        }
        names = tail;
    }
    false
}

/// A message's argument names, made when the crate builds: [`Names::new`] over the literals, a
/// repeated name or a name outside [`tokens`] failing the build (E0080). `#[derive(Explain)]`
/// writes it, and a hand-written [`Explain`] calls it.
///
/// ```
/// use siros_explain::names;
///
/// let names = names!("from", "to");
/// assert_eq!(
///     names.as_slice().iter().map(|name| name.as_str()).collect::<Vec<_>>(),
///     ["from", "to"]
/// );
/// ```
#[macro_export]
macro_rules! names {
    ($($name:literal),* $(,)?) => {
        const {
            match $crate::Names::new([$($name),*]) {
                ::core::option::Option::Some(names) => names,
                ::core::option::Option::None => {
                    ::core::panic!(::core::concat!("Names refuses", $(" ", $name),*))
                }
            }
        }
    };
}

/// A message's `N` argument names: each one or more [`tokens`], none twice. [`names!`] makes one
/// when the crate builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Names<const N: usize>([ArgName; N]);

impl<const N: usize> Names<N> {
    /// The names; `None` for a name that is no tokens or a name given twice.
    #[must_use]
    pub const fn new(names: [&'static str; N]) -> Option<Self> {
        let mut rest: &[&'static str] = &names;
        while let [name, tail @ ..] = rest {
            if !tokens(name, 1) || among(name, tail) {
                return None;
            }
            rest = tail;
        }
        let mut out = [ArgName(""); N];
        let (mut slots, mut rest): (&mut [ArgName], &[&'static str]) = (&mut out, &names);
        while let ([slot, slots_tail @ ..], [name, tail @ ..]) = (slots, rest) {
            *slot = ArgName(name);
            slots = slots_tail;
            rest = tail;
        }
        Some(Self(out))
    }

    /// The names, in order.
    #[must_use]
    pub const fn as_slice(&self) -> &[ArgName] {
        &self.0
    }

    /// The names, by value.
    pub(crate) const fn into_array(self) -> [ArgName; N] {
        self.0
    }
}

/// A value a message interpolates, of the kind its type declares: only [`Arg::of`] makes one.
#[derive(Debug, Clone)]
pub struct Arg<'a>(ArgValue<'a>);

impl<'a> Arg<'a> {
    /// The argument a value gives, of its type's kind.
    pub fn of<T: IntoArg + ?Sized>(value: &'a T) -> Self {
        <T::Kind as Kind>::arg(value.arg(), sealed::Token(()))
    }

    /// The argument of a kind's value: [`Kind::arg`]'s.
    pub(crate) const fn held(value: ArgValue<'a>) -> Self {
        Self(value)
    }

    /// What it holds.
    #[must_use]
    pub const fn value(&self) -> &ArgValue<'a> {
        &self.0
    }

    /// What it holds, by value.
    pub(crate) fn into_value(self) -> ArgValue<'a> {
        self.0
    }
}

/// What an [`Arg`] holds, as the renderer reads it.
#[derive(Debug, Clone)]
pub enum ArgValue<'a> {
    /// An i18n query: a message, rendered as its own text.
    Message(&'a dyn Explain),
    /// A typed value, formatted with its module's format options, or the main module's when it
    /// stands alone.
    Value(Value),
    /// A name the code fixes, shown as code: an enum's code, a member, a parameter, a module.
    Name(&'static str),
    /// Several values, one or more, as the locale's list: each signature's reason, each path.
    List {
        /// The list it forms.
        kind: ListKind,
        /// The values.
        items: AllOf<Arg<'a>>,
    },
    /// An optional value the input left out.
    Absent,
    /// A text held by value: a stored query.
    Held(&'a Text),
    /// A text from the outside, shown as written: the last resort.
    Raw(&'a str),
}

/// Values compare by what they hold; a message by its identifier and arguments.
impl PartialEq for ArgValue<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Message(a), Self::Message(b)) => Text::of(*a) == Text::of(*b),
            (Self::Value(a), Self::Value(b)) => a == b,
            (Self::Name(a), Self::Name(b)) => a == b,
            (Self::List { kind: a, items: x }, Self::List { kind: b, items: y }) => {
                a == b
                    && x.items().len() == y.items().len()
                    && x.items()
                        .iter()
                        .zip(y.items())
                        .all(|(x, y)| x.value() == y.value())
            }
            (Self::Absent, Self::Absent) => true,
            (Self::Held(a), Self::Held(b)) => a == b,
            (Self::Raw(a), Self::Raw(b)) => a == b,
            _ => false,
        }
    }
}

/// A message's arguments, each under its name of [`Names`], so no name repeats. Only
/// [`Args::new`] and [`Args::none`] make one; nothing adds another message's arguments to them.
#[derive(Debug, Clone)]
pub struct Args<'a>(Vec<Named<'a>>);

/// One argument under its name.
#[derive(Debug, Clone)]
pub struct Named<'a> {
    pub(crate) name: ArgName,
    pub(crate) arg: Arg<'a>,
}

impl<'a> Named<'a> {
    /// The name.
    #[must_use]
    pub const fn name(&self) -> ArgName {
        self.name
    }

    /// The argument.
    #[must_use]
    pub const fn arg(&self) -> &Arg<'a> {
        &self.arg
    }
}

impl<'a> Args<'a> {
    /// No argument.
    #[must_use]
    pub const fn none() -> Self {
        Self(Vec::new())
    }

    /// The values under the names, in order: one value per name.
    #[must_use]
    pub fn new<const N: usize>(names: Names<N>, values: [Arg<'a>; N]) -> Self {
        let named = names.0.into_iter().zip(values);
        Self(named.map(|(name, arg)| Named { name, arg }).collect())
    }

    /// The arguments, in order.
    #[must_use]
    pub fn as_slice(&self) -> &[Named<'a>] {
        &self.0
    }

    /// The arguments, by value.
    pub(crate) fn into_vec(self) -> Vec<Named<'a>> {
        self.0
    }
}

/// The kind of value an argument takes, which decides the functions a message may apply to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArgKind {
    /// An i18n query.
    Message,
    /// A count.
    Count,
    /// An exact decimal.
    Decimal,
    /// A date.
    Date,
    /// A time of day.
    Time,
    /// A date and a time.
    DateTime,
    /// An amount in a currency.
    Amount,
    /// A currency.
    Currency,
    /// A name the code fixes.
    Name,
    /// Several values.
    List,
    /// A stored text.
    Text,
    /// A text from the outside.
    Raw,
}

/// Whether a parameter's value may be absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Presence {
    /// Always given.
    Required,
    /// Absent when the input left it out.
    Optional,
}

pub(crate) mod sealed {
    /// Seals [`Kind`](crate::Kind): the kinds are [`kind`](crate::kind)'s.
    pub trait Sealed {}

    /// Seals [`Kind::arg`](crate::Kind::arg): only the crate makes one, so only
    /// [`Arg::of`](crate::Arg::of) calls it.
    #[derive(Debug, Clone, Copy)]
    pub struct Token(pub(crate) ());
}

/// A kind of value: the [`ArgKind`] a declaration records, and the value a type of the kind
/// gives. Sealed: the kinds are [`kind`](crate::kind)'s.
pub trait Kind: sealed::Sealed {
    /// The kind a declaration records.
    const KIND: ArgKind;
    /// Whether the value may be absent.
    const PRESENCE: Presence = Presence::Required;
    /// What a value of the kind gives.
    type Of<'a>;
    /// That value as an argument. Its token is the crate's, so [`Arg::of`] alone calls it.
    fn arg<'a>(value: Self::Of<'a>, token: sealed::Token) -> Arg<'a>;
}

/// A value that a message can name: its kind, as a type, and the value of that kind. A type
/// without it, a secret's above all, is no argument.
pub trait IntoArg {
    /// The kind of value: one of [`kind`](crate::kind)'s.
    type Kind: Kind;
    /// The value, of its kind.
    fn arg(&self) -> <Self::Kind as Kind>::Of<'_>;
}
