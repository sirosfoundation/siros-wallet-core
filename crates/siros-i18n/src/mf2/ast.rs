//! MF2's data model (spec/data-model): what the parser makes of a message. Names, identifiers
//! and variant keys are held as the parse's [`Hold`](crate::normal::Hold) holds them; literals and
//! text as written. Attributes are dropped: they have no effect on formatting.

/// A message: its declarations and its body.
#[derive(Debug)]
pub(crate) struct Message {
    pub(crate) declarations: Vec<Declaration>,
    pub(crate) body: Body,
}

/// A declaration.
#[derive(Debug)]
pub(crate) enum Declaration {
    /// `.input {$name …}`: an external value, with the function applied to it.
    Input {
        name: String,
        function: Option<Function>,
    },
    /// `.local $name = {…}`.
    Local {
        name: String,
        expression: Expression,
    },
}

/// A message's body.
#[derive(Debug)]
pub(crate) enum Body {
    /// A single pattern.
    Pattern(Pattern),
    /// `.match` over selectors, and its variants.
    Matcher {
        selectors: Vec<String>,
        variants: Vec<Variant>,
    },
}

/// A variant: its keys, one per selector, and its pattern.
#[derive(Debug)]
pub(crate) struct Variant {
    pub(crate) keys: Vec<Key>,
    pub(crate) pattern: Pattern,
}

/// A variant key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Key {
    /// A literal, held.
    Literal(String),
    /// `*`.
    CatchAll,
}

/// A pattern's parts, in order.
pub(crate) type Pattern = Vec<Part>;

/// A part of a pattern.
#[derive(Debug)]
pub(crate) enum Part {
    /// Text, its escapes resolved.
    Text(String),
    /// A placeholder's expression.
    Expression(Expression),
    /// A placeholder's markup.
    Markup(Markup),
}

/// An expression: an operand with an optional function, or a function alone.
#[derive(Debug)]
pub(crate) enum Expression {
    /// `{|literal|}`, `{$variable}`, `{… :function}`.
    Operand {
        operand: Operand,
        function: Option<Function>,
    },
    /// `{:function}`.
    Function(Function),
}

/// A literal or a variable.
#[derive(Debug, Clone)]
pub(crate) enum Operand {
    /// A literal's string value.
    Literal(String),
    /// A variable's name, held.
    Variable(String),
}

/// A function and its options.
#[derive(Debug)]
pub(crate) struct Function {
    pub(crate) name: String,
    pub(crate) options: Vec<Opt>,
}

/// An option: its identifier, held, and its value.
#[derive(Debug)]
pub(crate) struct Opt {
    pub(crate) name: String,
    pub(crate) value: Operand,
}

/// Markup.
#[derive(Debug)]
pub(crate) struct Markup {
    pub(crate) kind: MarkupKind,
    pub(crate) name: String,
    pub(crate) options: Vec<Opt>,
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

impl Expression {
    /// The expression's operand and function.
    pub(crate) const fn parts(&self) -> (Option<&Operand>, Option<&Function>) {
        match self {
            Self::Operand { operand, function } => (Some(operand), function.as_ref()),
            Self::Function(function) => (None, Some(function)),
        }
    }
}
