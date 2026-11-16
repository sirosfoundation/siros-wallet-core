//! The extension point of a context's functions: a [`Formatter`] defines functions from the
//! sections of the locale files it reads, and formats and selects on the arguments its functions
//! take. A context holds the formatters its builder gives it; `:string` is the context's own.

use std::any::TypeId;

use siros_explain::Arg;

use crate::error::{FormatRule, Refusal};

/// A text's directionality: a message's, by its module's `@dir`, and a formatted value's, which
/// MF2's Default Bidi Strategy isolates it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Left to right.
    Ltr,
    /// Right to left.
    Rtl,
    /// Not known.
    Unknown,
}

/// A function a formatter defines, by the number the formatter gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FunctionId(pub u32);

/// A setting of a section a formatter reads: its key and its text, as the module writes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting<'s> {
    /// The key.
    pub key: &'s str,
    /// The text.
    pub text: &'s str,
}

/// What a value selects with: a variant key equal to its exact text matches first, then a key
/// equal to its category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    exact: String,
    category: Option<String>,
}

impl Selection {
    /// The selection by `exact`, then by `category` when it has one.
    #[must_use]
    pub const fn new(exact: String, category: Option<String>) -> Self {
        Self { exact, category }
    }

    /// The rank of `key` among the keys the value matches, from 0 for the best; `None` for a key
    /// it does not match.
    pub(crate) fn rank(&self, key: &str) -> Option<usize> {
        if self.exact == key {
            Some(0)
        } else if self.category.as_deref() == Some(key) {
            Some(1)
        } else {
            None
        }
    }
}

/// A family of functions: the sections it reads define them, and it formats and selects on the
/// values of the types each function takes. The context asks it, in this order: which sections
/// it reads, then each such section's settings as a module loads; which function a name calls,
/// and how a call's options and a selector's keys check, as a message compiles; and which
/// function a type takes by default, whether a function takes a type, and the text or the
/// selection of a value, as a message resolves.
pub trait Formatter: 'static {
    /// Whether it reads the section `section` (the name between the brackets).
    fn reads(&self, section: &str) -> bool;

    /// Loads the settings of its section `section`, of a module whose direction is `direction`.
    ///
    /// # Errors
    ///
    /// The [`FormatRule`] the settings break.
    fn load(
        &mut self,
        section: &str,
        settings: &[Setting<'_>],
        direction: Direction,
    ) -> Result<(), FormatRule>;

    /// The function the sections loaded so far define under `name`, without its colon.
    fn function(&self, name: &str) -> Option<FunctionId>;

    /// The name of `function`, without its colon.
    fn name(&self, function: FunctionId) -> &str;

    /// The function a value of the type `of` takes where the wording names none.
    fn default(&self, of: TypeId) -> Option<FunctionId>;

    /// Whether `function` takes a value of the type `of`.
    fn takes(&self, function: FunctionId, of: TypeId) -> bool;

    /// Checks a call's option `name` when a module loads: `text` is its literal, `None` where a
    /// variable gives it.
    ///
    /// # Errors
    ///
    /// [`Refusal::Option`] for an option the function does not take, or a literal it refuses.
    fn option(&self, function: FunctionId, name: &str, text: Option<&str>)
    -> Result<(), Refusal>;

    /// Checks `key`, a variant key of a selector that calls `function`.
    ///
    /// # Errors
    ///
    /// [`Refusal::Selector`] for a function that does not select, [`Refusal::Key`] for a key its
    /// selection never matches.
    fn key(&self, function: FunctionId, key: &str) -> Result<(), Refusal>;

    /// Whether `function` selects.
    fn selects(&self, function: FunctionId) -> bool;

    /// Writes `value` formatted by `function` with the call's `options`, each name and text,
    /// to `out`, and gives the formatted text's direction.
    ///
    /// # Errors
    ///
    /// [`Refusal::Operand`] for a value the function refuses, [`Refusal::Option`] for an option
    /// text it refuses.
    fn format(
        &self,
        function: FunctionId,
        value: &dyn Arg,
        options: &[(&str, &str)],
        out: &mut String,
    ) -> Result<Direction, Refusal>;

    /// What `value` selects with under `function` and the call's `options`.
    ///
    /// # Errors
    ///
    /// As [`Formatter::format`].
    fn select(
        &self,
        function: FunctionId,
        value: &dyn Arg,
        options: &[(&str, &str)],
    ) -> Result<Selection, Refusal>;
}
