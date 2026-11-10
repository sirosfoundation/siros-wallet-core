//! MF2's data model (spec/data-model): what the parser makes of a message, borrowed from its
//! source. Names, identifiers and variant keys are held as the parse's
//! [`Hold`](crate::normal::Hold) holds them; literals and text as written, their escapes
//! resolved. Attributes are dropped: they have no effect on formatting.

use std::borrow::Cow;

/// A message: its declarations and its body.
#[derive(Debug)]
pub(crate) struct Message<'s> {
    pub(crate) declarations: Vec<Declaration<'s>>,
    pub(crate) body: Body<'s>,
}

/// A declaration.
#[derive(Debug)]
pub(crate) enum Declaration<'s> {
    /// `.input {$name …}`: an external value, with the function applied to it.
    Input {
        name: Cow<'s, str>,
        function: Option<Function<'s>>,
    },
    /// `.local $name = {…}`.
    Local {
        name: Cow<'s, str>,
        expression: Expression<'s>,
    },
}

/// A message's body.
#[derive(Debug)]
pub(crate) enum Body<'s> {
    /// A single pattern.
    Pattern(Pattern<'s>),
    /// `.match` over selectors, and its variants.
    Matcher {
        selectors: Vec<Cow<'s, str>>,
        variants: Vec<Variant<'s>>,
    },
}

/// A variant: its keys and its pattern.
#[derive(Debug)]
pub(crate) struct Variant<'s> {
    pub(crate) keys: Vec<Key<'s>>,
    pub(crate) pattern: Pattern<'s>,
}

/// A variant key.
#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) enum Key<'s> {
    /// A literal, held.
    Literal(Cow<'s, str>),
    /// `*`.
    CatchAll,
}

/// A pattern's parts, in order.
pub(crate) type Pattern<'s> = Vec<Part<'s>>;

/// A part of a pattern.
#[derive(Debug)]
pub(crate) enum Part<'s> {
    /// Text.
    Text(Cow<'s, str>),
    /// A placeholder's expression.
    Expression(Expression<'s>),
    /// A placeholder's markup.
    Markup(Markup<'s>),
}

/// An expression: an operand with an optional function, or a function alone.
#[derive(Debug)]
pub(crate) enum Expression<'s> {
    /// `{|literal|}`, `{$variable}`, `{… :function}`.
    Operand {
        operand: Operand<'s>,
        function: Option<Function<'s>>,
    },
    /// `{:function}`.
    Function(Function<'s>),
}

impl<'s> Expression<'s> {
    /// The expression's operand and function.
    pub(crate) const fn parts(&self) -> (Option<&Operand<'s>>, Option<&Function<'s>>) {
        match self {
            Self::Operand { operand, function } => (Some(operand), function.as_ref()),
            Self::Function(function) => (None, Some(function)),
        }
    }
}

/// A literal or a variable.
#[derive(Debug)]
pub(crate) enum Operand<'s> {
    /// A literal's string value.
    Literal(Cow<'s, str>),
    /// A variable's name, held.
    Variable(Cow<'s, str>),
}

/// A function and its options.
#[derive(Debug)]
pub(crate) struct Function<'s> {
    pub(crate) name: Cow<'s, str>,
    pub(crate) options: Vec<Opt<'s>>,
}

/// An option: its identifier, held, and its value.
#[derive(Debug)]
pub(crate) struct Opt<'s> {
    pub(crate) name: Cow<'s, str>,
    pub(crate) value: Operand<'s>,
}

/// Markup.
#[derive(Debug)]
pub(crate) struct Markup<'s> {
    pub(crate) kind: MarkupKind,
    pub(crate) name: Cow<'s, str>,
    pub(crate) options: Vec<Opt<'s>>,
}

/// Which markup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MarkupKind {
    /// `{#name}`.
    Open,
    /// `{#name/}`.
    Standalone,
    /// `{/name}`.
    Close,
}
