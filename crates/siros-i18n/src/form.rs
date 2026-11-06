//! A module's render form: for each locale it supports, every message as literal text,
//! placeholders compiled by their format modules, selections over normalized keys, and markup.
//! The loader makes it, a package carries it, and the renderer executes it.

use std::fmt;

use siros_explain::{ArgKind, Entry, IntoArg, ParamKind, ParamName, Presence, Value, kind};
#[cfg(feature = "load")]
use siros_explain::{Message, ModuleId, Param};

#[cfg(feature = "load")]
use crate::format::Direction;
#[cfg(feature = "load")]
use crate::locale::LocaleTag;
use crate::sink::Style;

/// Whether a presentation that draws from a module must stay in a language the End-User
/// understands. PaSO and TS12 set it for their modules (View §4, TS12 §3.3.1); the app answers for
/// a module no specification governs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanguagePolicy {
    /// It must: with no tag of the priority list for every module, the entry is excluded.
    Understood,
    /// It may take a tag of the app's fallback list.
    Any,
}

/// A module in its render form: its identity, its digest, its language policy, and each locale's
/// compiled messages, in the order its sources were given. Only the loader makes one.
#[cfg(feature = "load")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledModule {
    pub(crate) id: ModuleId,
    pub(crate) digest: crate::render::ModuleDigest,
    pub(crate) policy: LanguagePolicy,
    pub(crate) locales: Vec<LocaleForm>,
}

/// The kind of a bare value or list, which a main module's format of that kind renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BareKind {
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
    /// A list.
    List,
}

impl BareKind {
    /// Every kind, in the order a main module compiles their formats and a package writes them.
    pub(crate) const ALL: [Self; 8] = [
        Self::Count,
        Self::Decimal,
        Self::Date,
        Self::Time,
        Self::DateTime,
        Self::Amount,
        Self::Currency,
        Self::List,
    ];

    /// The kind of a typed value.
    pub(crate) const fn of(value: &Value) -> Self {
        match value {
            Value::Count(_) => Self::Count,
            Value::Decimal(_) => Self::Decimal,
            Value::Date(_) => Self::Date,
            Value::Time { .. } => Self::Time,
            Value::DateTime(_) => Self::DateTime,
            Value::Amount(_) => Self::Amount,
            Value::Currency(_) => Self::Currency,
        }
    }

    /// The argument kind it is.
    pub(crate) const fn arg_kind(self) -> ArgKind {
        match self {
            Self::Count => ArgKind::Count,
            Self::Decimal => ArgKind::Decimal,
            Self::Date => ArgKind::Date,
            Self::Time => ArgKind::Time,
            Self::DateTime => ArgKind::DateTime,
            Self::Amount => ArgKind::Amount,
            Self::Currency => ArgKind::Currency,
            Self::List => ArgKind::List,
        }
    }

    /// Its name, as a refusal names it.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Decimal => "decimal",
            Self::Date => "date",
            Self::Time => "time",
            Self::DateTime => "date_time",
            Self::Amount => "amount",
            Self::Currency => "currency",
            Self::List => "list",
        }
    }
}

impl fmt::Display for BareKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl IntoArg for BareKind {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.name()
    }
}

/// One locale's compiled messages, sorted by identifier, its direction, and its formats of
/// bare values.
#[cfg(feature = "load")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocaleForm {
    pub(crate) locale: LocaleTag,
    pub(crate) direction: Direction,
    pub(crate) messages: Vec<MessageForm>,
    pub(crate) bare: BareCalls,
}

#[cfg(feature = "load")]
impl LocaleForm {
    /// The message `id`.
    pub(crate) fn message(&self, id: &str) -> Option<&MessageForm> {
        let index = self
            .messages
            .binary_search_by(|form| form.id.as_str().cmp(id))
            .ok()?;
        self.messages.get(index)
    }
}

/// The main module's format of a bare value of each kind, where a registered format module
/// provides the kind's function.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct BareCalls {
    count: Option<CompiledCall>,
    decimal: Option<CompiledCall>,
    date: Option<CompiledCall>,
    time: Option<CompiledCall>,
    date_time: Option<CompiledCall>,
    amount: Option<CompiledCall>,
    currency: Option<CompiledCall>,
    list: Option<CompiledCall>,
}

impl BareCalls {
    const fn slot(&mut self, kind: BareKind) -> &mut Option<CompiledCall> {
        match kind {
            BareKind::Count => &mut self.count,
            BareKind::Decimal => &mut self.decimal,
            BareKind::Date => &mut self.date,
            BareKind::Time => &mut self.time,
            BareKind::DateTime => &mut self.date_time,
            BareKind::Amount => &mut self.amount,
            BareKind::Currency => &mut self.currency,
            BareKind::List => &mut self.list,
        }
    }

    /// Sets the format of `kind`.
    pub(crate) fn set(&mut self, kind: BareKind, call: CompiledCall) {
        *self.slot(kind) = Some(call);
    }

    /// The format of `kind`; `None` when no registered format module provides it.
    pub(crate) const fn get(&self, kind: BareKind) -> Option<&CompiledCall> {
        match kind {
            BareKind::Count => self.count.as_ref(),
            BareKind::Decimal => self.decimal.as_ref(),
            BareKind::Date => self.date.as_ref(),
            BareKind::Time => self.time.as_ref(),
            BareKind::DateTime => self.date_time.as_ref(),
            BareKind::Amount => self.amount.as_ref(),
            BareKind::Currency => self.currency.as_ref(),
            BareKind::List => self.list.as_ref(),
        }
    }

    /// Every format set.
    #[cfg(feature = "load")]
    pub(crate) fn calls(&self) -> impl Iterator<Item = &CompiledCall> {
        [
            &self.count,
            &self.decimal,
            &self.date,
            &self.time,
            &self.date_time,
            &self.amount,
            &self.currency,
            &self.list,
        ]
        .into_iter()
        .flatten()
    }
}

/// One message, compiled: its identifier, its declaration's parameters, its expressions, and its
/// body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MessageForm {
    pub(crate) id: String,
    pub(crate) params: Vec<ParamForm>,
    pub(crate) expressions: Vec<Expression>,
    pub(crate) body: BodyForm,
}

/// A parameter of a message's declaration: its name, its value's kind, and whether it may be
/// absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParamForm {
    pub(crate) name: ParamName,
    pub(crate) kind: ArgKind,
    pub(crate) presence: Presence,
}

#[cfg(feature = "load")]
impl ParamForm {
    /// The form of each parameter `message` declares, in order.
    pub(crate) fn of_message(message: &Message) -> Vec<Self> {
        let form = |param: &Param| Self {
            name: ParamName::from(param.name()),
            kind: param.kind().kind(),
            presence: param.kind().presence(),
        };
        message.params().iter().map(form).collect()
    }
}

impl ParamForm {
    /// The form of a parameter a converter declares.
    pub(crate) fn of_param(param: &Entry<ParamName, ParamKind>) -> Self {
        Self {
            name: param.key().clone(),
            kind: param.value().kind(),
            presence: param.value().presence(),
        }
    }
}

/// An expression: its root operand, the call its format module compiled, and its `u:dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Expression {
    pub(crate) root: Root,
    pub(crate) call: CompiledCall,
    pub(crate) dir: Dir,
}

/// A compiled placeholder: its format module's identity, and the bytes the module's render half
/// reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledCall {
    pub(crate) format: String,
    pub(crate) bytes: Vec<u8>,
}

/// What an expression's chain of calls starts from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Root {
    /// No operand.
    None,
    /// A literal's string value.
    Literal(String),
    /// The parameter at this index.
    Argument(usize),
}

/// `u:dir`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    /// `inherit`, the default.
    Inherit,
    /// `ltr`.
    Ltr,
    /// `rtl`.
    Rtl,
    /// `auto`.
    Auto,
}

/// A message's body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BodyForm {
    /// One pattern.
    Pattern(Vec<PartForm>),
    /// A selection.
    Select {
        selectors: Vec<SelectorForm>,
        variants: Vec<VariantForm>,
    },
}

/// A selector: its expression, and the distinct literal keys its variants give it, in NFC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelectorForm {
    pub(crate) expression: usize,
    pub(crate) keys: Vec<String>,
}

/// A variant: one key per selector, and its pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VariantForm {
    pub(crate) keys: Vec<KeyRef>,
    pub(crate) pattern: Vec<PartForm>,
}

/// A variant's key for one selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyRef {
    /// `*`.
    CatchAll,
    /// The selector's key at this index.
    Key(usize),
}

/// A part of a compiled pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PartForm {
    /// Text.
    Text(String),
    /// The message's expression at this index, formatted.
    Expression(usize),
    /// Markup opening a style.
    Open(Style),
    /// Markup closing the innermost open style.
    Close(Style),
}
