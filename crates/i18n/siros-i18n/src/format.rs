//! A context's functions: `:string`, and those its formatters define. The load checks each
//! [`Chain`] for the use a placeholder, a selector or an option makes of it; a resolution formats
//! the chain's value, selects on it, or takes its text.
//!
//! A chain's outermost call names the function. That function formats the value the chain starts
//! from, with the options of every call of the same function along the chain, an outer call's
//! option over an inner one's.

use std::any::TypeId;
use std::fmt;

use siros_explain::Arg;

use crate::chain::{Call, Chain, Failure, Root};
use crate::error::Refusal;
use crate::formatter::{Direction, Formatter, FunctionId, Selection, Setting};
use crate::scope::Scope;

/// A function of a context: `:string`, or one a formatter defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Function {
    String,
    Formatted { by: usize, id: FunctionId },
}

/// The name of `:string`.
pub(crate) const STRING: &str = "string";

/// A context's formatters, in the order its builder gives them: an earlier formatter's
/// functions and defaults come before a later one's.
#[derive(Default)]
pub(crate) struct Formatters(Vec<Box<dyn Formatter>>);

impl fmt::Debug for Formatters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Formatters({})", self.0.len())
    }
}

impl Formatters {
    /// Adds `formatter` after the others.
    pub(crate) fn push(&mut self, formatter: Box<dyn Formatter>) {
        self.0.push(formatter);
    }

    /// The formatter that reads the section `section`; `None` for a section of messages.
    pub(crate) fn reader(&mut self, section: &str) -> Option<&mut dyn Formatter> {
        self.0
            .iter_mut()
            .find(|formatter| formatter.reads(section))
            .map(|formatter| &mut **formatter as &mut dyn Formatter)
    }

    /// Loads `settings` into the formatter that reads `section`; `false` for a section no
    /// formatter reads.
    ///
    /// # Errors
    ///
    /// The formatter's [`FormatRule`](crate::FormatRule).
    pub(crate) fn load(
        &mut self,
        section: &str,
        settings: &[Setting<'_>],
        direction: Direction,
    ) -> Result<bool, crate::FormatRule> {
        match self.reader(section) {
            Some(formatter) => formatter.load(section, settings, direction).map(|()| true),
            None => Ok(false),
        }
    }

    /// The function `name` calls: `:string`, else the first formatter's that defines it.
    pub(crate) fn named(&self, name: &str) -> Option<Function> {
        if name == STRING {
            return Some(Function::String);
        }
        self.0.iter().enumerate().find_map(|(by, formatter)| {
            formatter
                .function(name)
                .map(|id| Function::Formatted { by, id })
        })
    }

    fn formatter(&self, by: usize) -> Option<&dyn Formatter> {
        self.0.get(by).map(|formatter| &**formatter)
    }

    /// The name of `function`.
    pub(crate) fn name(&self, function: Function) -> &str {
        match function {
            Function::String => STRING,
            Function::Formatted { by, id } => self.formatter(by).map_or(STRING, |f| f.name(id)),
        }
    }

    /// The function a value of the type `of` takes where the wording names none: the first
    /// formatter's default, else `:string`.
    pub(crate) fn default_for(&self, of: TypeId) -> Function {
        self.0
            .iter()
            .enumerate()
            .find_map(|(by, formatter)| {
                formatter
                    .default_for(of)
                    .map(|id| Function::Formatted { by, id })
            })
            .unwrap_or(Function::String)
    }

    /// Whether `function` takes a value of the type `of`: `:string` takes every type.
    pub(crate) fn takes(&self, function: Function, of: TypeId) -> bool {
        match function {
            Function::String => true,
            Function::Formatted { by, id } => self.formatter(by).is_some_and(|f| f.takes(id, of)),
        }
    }

    /// Checks a call's option: `:string` ignores the options a call writes, as
    /// spec/functions/README.md permits.
    ///
    /// # Errors
    ///
    /// The formatter's [`Refusal`].
    pub(crate) fn option(
        &self,
        function: Function,
        name: &str,
        text: Option<&str>,
    ) -> Result<(), Refusal> {
        match function {
            Function::String => Ok(()),
            Function::Formatted { by, id } => self
                .formatter(by)
                .ok_or(Refusal::Operand)?
                .option(id, name, text),
        }
    }

    /// Checks a literal operand of a call of `function`: `:string` takes every literal.
    ///
    /// # Errors
    ///
    /// The formatter's [`Refusal`].
    pub(crate) fn literal(&self, function: Function, text: &str) -> Result<(), Refusal> {
        match function {
            Function::String => Ok(()),
            Function::Formatted { by, id } => {
                self.formatter(by).ok_or(Refusal::Operand)?.literal(id, text)
            }
        }
    }

    /// Checks a variant key of a selector calling `function`: `:string` matches any key.
    ///
    /// # Errors
    ///
    /// The formatter's [`Refusal`].
    pub(crate) fn key(&self, function: Function, key: &str) -> Result<(), Refusal> {
        match function {
            Function::String => Ok(()),
            Function::Formatted { by, id } => {
                self.formatter(by).ok_or(Refusal::Operand)?.key(id, key)
            }
        }
    }

    /// Whether `function` selects: `:string` selects by the operand's text.
    pub(crate) fn selects(&self, function: Function) -> bool {
        match function {
            Function::String => true,
            Function::Formatted { by, id } => self.formatter(by).is_some_and(|f| f.selects(id)),
        }
    }
}

/// Checks the chain for its use at a placeholder or as an option's value.
///
/// # Errors
///
/// [`Refusal::Operand`] for a chain without an operand, a chain of `:string` with a call of
/// another function, and a literal operand the function refuses.
pub(crate) fn check(chain: &Chain<'_>, formatters: &Formatters) -> Result<(), Refusal> {
    let function = chain.outer.function;
    match (function, chain.root) {
        (Function::String, _) => crate::string::check(chain),
        (Function::Formatted { .. }, Root::None) => Err(Refusal::Operand),
        (Function::Formatted { .. }, Root::Literal(text)) => formatters.literal(function, text),
        (Function::Formatted { .. }, Root::Argument(_)) => Ok(()),
    }
}

/// Checks the chain for its use as a selector, and gives its function.
///
/// # Errors
///
/// The [`Refusal`] of [`check`], and [`Refusal::Selector`] for a function that does not select.
pub(crate) fn selecting(chain: &Chain<'_>, formatters: &Formatters) -> Result<Function, Refusal> {
    check(chain, formatters)?;
    let function = chain.outer.function;
    if formatters.selects(function) {
        Ok(function)
    } else {
        Err(Refusal::Selector)
    }
}

/// The chain's value as an option's value: the text of the operand it starts from.
///
/// # Errors
///
/// [`Failure::Operand`] for a chain without an operand, and [`Failure::Unresolved`] for an
/// argument the message does not give.
pub(crate) fn value<'m>(chain: &Chain<'m>, scope: &Scope<'m>) -> Result<&'m str, Failure> {
    crate::string::value(chain, scope)
}

/// The value the chain starts from.
fn operand<'m>(chain: &Chain<'m>, scope: &Scope<'m>) -> Result<&'m dyn Arg, Failure> {
    match chain.root {
        Root::None => Err(Failure::Operand),
        Root::Literal(text) => Ok(text),
        Root::Argument(key) => scope.arg(key),
    }
}

/// The failure at resolution of a formatter's refusal.
fn failure(refusal: Refusal) -> Failure {
    match refusal {
        Refusal::Option { option } => Failure::Option(option),
        Refusal::Operand | Refusal::Key { .. } | Refusal::Selector => Failure::Operand,
    }
}

/// The chain's value formatted, and the formatted text's direction.
///
/// # Errors
///
/// [`Failure`] for an operand or an option text the function refuses, or an argument the
/// message does not give.
pub(crate) fn format(chain: &Chain<'_>, scope: &Scope<'_>) -> Result<(String, Direction), Failure> {
    match chain.outer.function {
        Function::String => {
            crate::string::value(chain, scope).map(|text| (text.to_owned(), Direction::Unknown))
        }
        Function::Formatted { by, id } => {
            let options = chain.options(scope)?;
            let value = operand(chain, scope)?;
            let formatter = scope.formatters.formatter(by).ok_or(Failure::Operand)?;
            let mut out = String::new();
            let direction = formatter
                .format(id, value, &options, &mut out)
                .map_err(failure)?;
            Ok((out, direction))
        }
    }
}

/// What the chain's value selects with.
///
/// # Errors
///
/// [`Failure`] as [`format`].
pub(crate) fn selected(chain: &Chain<'_>, scope: &Scope<'_>) -> Result<Selection, Failure> {
    match chain.outer.function {
        Function::String => crate::string::value(chain, scope)
            .map(|text| Selection::new(text.to_owned(), None)),
        Function::Formatted { by, id } => {
            let options = chain.options(scope)?;
            let value = operand(chain, scope)?;
            let formatter = scope.formatters.formatter(by).ok_or(Failure::Operand)?;
            formatter.select(id, value, &options).map_err(failure)
        }
    }
}

/// The call of `function` without options, named `name`.
pub(crate) fn bare(function: Function, name: &str) -> Call {
    Call::new(function, std::borrow::Cow::Owned(name.to_owned()), Vec::new())
}
