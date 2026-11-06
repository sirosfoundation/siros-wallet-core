//! Format modules. Each MF2 function family is one: its load half, a [`FormatCompiler`], parses
//! the options a module defines for it in each language and compiles each placeholder that calls
//! one of its functions; its render half, a [`FormatRenderer`], formats a value with a compiled
//! placeholder and selects a variant. `:string` is built in; a build registers the others.

#[cfg(feature = "render")]
use std::marker::PhantomData;

#[cfg(feature = "render")]
use siros_explain::{AllOf, ListKind, Value};
#[cfg(feature = "load")]
use siros_explain::{ArgKind, Keyed};

#[cfg(feature = "render")]
use crate::error::RenderError;
#[cfg(feature = "load")]
use crate::error::{ModuleError, Refusal, RefusedOption};
#[cfg(feature = "load")]
use crate::locale::LocaleTag;
#[cfg(feature = "render")]
use crate::sink::Sink;

/// A format module's identity, which each compiled placeholder records: one or more tokens, as a
/// [`Domain`](siros_explain::Domain) is (`number`, `currency`). A format module makes its own with
/// `siros_explain::checked!`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FormatId(&'static str);

impl FormatId {
    /// The identity; `None` for a text that is no tokens.
    #[must_use]
    pub const fn new(id: &'static str) -> Option<Self> {
        match siros_explain::Domain::new(id) {
            Some(_) => Some(Self(id)),
            None => None,
        }
    }

    /// Its text.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for FormatId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl siros_explain::IntoArg for FormatId {
    type Kind = siros_explain::kind::Name;

    fn arg(&self) -> &'static str {
        self.0
    }
}

/// What a placeholder's function applies to, as the loader hands it to the function's module.
#[cfg(feature = "load")]
#[derive(Debug, Clone, Copy)]
pub enum Operand<'c> {
    /// No operand: `{:function}`.
    None,
    /// A literal's string value.
    Literal(&'c str),
    /// An argument of the key's declaration, of this kind.
    Argument(ArgKind),
    /// The value of a declaration whose expression called a function: `$x` after
    /// `.input {$x :integer}`. Its call holds that function, its options and its own operand.
    Call(&'c Call<'c>),
}

/// How the message uses an expression's value.
#[cfg(feature = "load")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Uses {
    format: bool,
    select: bool,
}

#[cfg(feature = "load")]
impl Uses {
    /// The uses, `format` in a placeholder and `select` as a selector.
    pub(crate) const fn new(format: bool, select: bool) -> Self {
        Self { format, select }
    }

    /// Whether a placeholder formats the value.
    #[must_use]
    pub const fn formats(self) -> bool {
        self.format
    }

    /// Whether a selector selects on the value.
    #[must_use]
    pub const fn selects(self) -> bool {
        self.select
    }
}

/// A function call as the loader hands it to its format module. Only the loader makes one, for a
/// function the module lists in `functions`.
#[cfg(feature = "load")]
#[derive(Debug, Clone, Copy)]
pub struct Call<'c> {
    function: &'static str,
    operand: Operand<'c>,
    options: &'c Keyed<&'c str, &'c str>,
    uses: Uses,
}

#[cfg(feature = "load")]
impl<'c> Call<'c> {
    pub(crate) const fn new(
        function: &'static str,
        operand: Operand<'c>,
        options: &'c Keyed<&'c str, &'c str>,
        uses: Uses,
    ) -> Self {
        Self {
            function,
            operand,
            options,
            uses,
        }
    }

    /// The function, without its colon: one of the module's `functions`.
    #[must_use]
    pub const fn function(&self) -> &'static str {
        self.function
    }

    /// The operand.
    #[must_use]
    pub const fn operand(&self) -> Operand<'c> {
        self.operand
    }

    /// The options, each a literal, each name once; the `u:` options are the loader's and stay
    /// out.
    #[must_use]
    pub const fn options(&self) -> &'c Keyed<&'c str, &'c str> {
        self.options
    }

    /// How the message uses the call's value.
    #[must_use]
    pub const fn uses(&self) -> Uses {
        self.uses
    }
}

/// One language's options of one format, as a module defines them: each of the format's
/// `options`, in its order. Only the loader makes one.
#[cfg(feature = "load")]
#[derive(Debug, Clone, Copy)]
pub struct LanguageFormats<'m> {
    locale: &'m LocaleTag,
    direction: Direction,
    options: &'m Keyed<&'static str, &'m str>,
}

/// One option of a [`LanguageFormats`]: its name, one of the format's `options`, and its text as
/// the module writes it.
#[cfg(feature = "load")]
#[derive(Debug, Clone, Copy)]
pub struct FormatOption<'m> {
    name: &'static str,
    text: &'m str,
}

#[cfg(feature = "load")]
impl<'m> FormatOption<'m> {
    /// The name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The text.
    #[must_use]
    pub const fn text(&self) -> &'m str {
        self.text
    }

    /// The format's refusal of this option's text.
    #[must_use]
    pub fn refuse(&self) -> RefusedOption {
        RefusedOption::new(self.name, self.text)
    }
}

#[cfg(feature = "load")]
impl<'m> LanguageFormats<'m> {
    pub(crate) const fn new(
        locale: &'m LocaleTag,
        direction: Direction,
        options: &'m Keyed<&'static str, &'m str>,
    ) -> Self {
        Self {
            locale,
            direction,
            options,
        }
    }

    /// The language.
    #[must_use]
    pub const fn locale(&self) -> &'m LocaleTag {
        self.locale
    }

    /// The language's direction, as its resource's `@dir` gives it.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Each option, in the format's order.
    pub fn options(&self) -> impl Iterator<Item = FormatOption<'m>> + use<'m> {
        self.options.entries().iter().map(|entry| FormatOption {
            name: entry.key(),
            text: entry.value(),
        })
    }

    /// The option `name`; `None` for a name outside the format's `options`.
    #[must_use]
    pub fn option(&self, name: &str) -> Option<FormatOption<'m>> {
        self.options().find(|option| option.name == name)
    }

    /// The option `name`, one of the format's `options`, each of which the loader gives.
    ///
    /// # Errors
    ///
    /// [`RefusedOption`] for a name outside the format's `options`, which the loader reports as
    /// [`ModuleError::UndeclaredOption`].
    pub fn require(&self, name: &'static str) -> Result<FormatOption<'m>, RefusedOption> {
        self.option(name)
            .ok_or_else(|| RefusedOption::undeclared(name))
    }
}

/// A format module's load half: the wallet's loader parses the options a module defines for it,
/// language by language, and compiles each placeholder of the module that calls one of its
/// functions with the parsed options.
///
/// # Implementing
///
/// `id`, `functions` and `options` are constants; the loader refuses two load halves sharing a
/// `FormatId` or a function (`ModuleError::Compiler`). `parse` reads the option texts a module
/// defines per language and refuses one its format does not take, and the compiled form it
/// writes is what [`FormatRenderer`] of the same `FormatId` reads under the package's root.
/// siros-i18n's format modules implement both halves.
#[cfg(feature = "load")]
pub trait FormatCompiler: Send + Sync {
    /// The module.
    fn id(&self) -> FormatId;
    /// The MF2 functions it provides, without their colons: `number`, `siros:date`.
    fn functions(&self) -> &'static [&'static str];
    /// The options a module that calls its functions defines for every language it supports.
    fn options(&self) -> &'static [&'static str];
    /// One language's options, parsed into the format's own value.
    ///
    /// # Errors
    ///
    /// [`RefusedOption`], made by [`FormatOption::refuse`], for an option whose text the format's
    /// grammar refuses.
    fn parse(
        &self,
        language: &LanguageFormats<'_>,
    ) -> Result<Box<dyn ParsedFormats>, RefusedOption>;
}

/// One language's options of one format, as its compiler parsed them; the loaded module compiles
/// each placeholder from them.
#[cfg(feature = "load")]
pub trait ParsedFormats: Send + Sync {
    /// The placeholder, compiled into the bytes its render half reads.
    ///
    /// # Errors
    ///
    /// [`Refusal`] for an operand, an option or a use the function refuses.
    fn compile(&self, call: &Call<'_>) -> Result<Vec<u8>, Refusal>;
}

/// The format modules' load halves the wallet registers, `:string`'s included. Only
/// [`Compilers::new`] makes one.
#[cfg(feature = "load")]
pub struct Compilers {
    compilers: Vec<&'static dyn FormatCompiler>,
}

#[cfg(feature = "load")]
impl Compilers {
    /// The wallet's load halves beside `:string`'s.
    ///
    /// # Errors
    ///
    /// [`ModuleError::Compiler`] when two share a [`FormatId`] or a function.
    pub fn new(compilers: &[&'static dyn FormatCompiler]) -> Result<Self, ModuleError> {
        let mut held: Vec<&'static dyn FormatCompiler> = vec![&crate::string::STRING];
        for &compiler in compilers {
            for earlier in &held {
                if earlier.id() == compiler.id() {
                    return Err(ModuleError::Compiler(compiler.id().as_str()));
                }
                if let Some(function) = compiler
                    .functions()
                    .iter()
                    .find(|f| earlier.functions().contains(f))
                {
                    return Err(ModuleError::Compiler(function));
                }
            }
            held.push(compiler);
        }
        Ok(Self { compilers: held })
    }

    /// The module that provides `function`, and the function's name as the module lists it.
    pub(crate) fn provider(
        &self,
        function: &str,
    ) -> Option<(&'static dyn FormatCompiler, &'static str)> {
        self.compilers.iter().find_map(|&compiler| {
            compiler
                .functions()
                .iter()
                .find(|&&f| f == function)
                .map(|&f| (compiler, f))
        })
    }
}

/// What a format module's render half formats or selects on.
#[cfg(feature = "render")]
#[derive(Debug, Clone, Copy)]
pub enum Input<'a> {
    /// No operand.
    None,
    /// A literal's string value.
    Literal(&'a str),
    /// A typed value.
    Value(&'a Value),
    /// A text: a name, a raw text, or a nested text rendered.
    Text(&'a str),
    /// A list's items, each rendered.
    List {
        /// The list it forms.
        kind: ListKind,
        /// The items, each rendered.
        items: &'a AllOf<String>,
    },
}

/// A text's directionality: a message's, by its locale's `@dir`, and a formatted value's, which
/// MF2's default bidi strategy isolates it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Left to right.
    Ltr,
    /// Right to left.
    Rtl,
    /// Not known.
    Unknown,
}

/// A format module's render half: what the matcher links.
#[cfg(feature = "render")]
pub trait FormatRenderer: Send + Sync {
    /// The module.
    fn id(&self) -> FormatId;
    /// The directionality of the value's formatted text.
    ///
    /// # Errors
    ///
    /// [`RenderError::Compiled`] for a compiled placeholder that does not read.
    fn direction(&self, compiled: &[u8], input: &Input<'_>) -> Result<Direction, RenderError>;
    /// Writes a value with a compiled placeholder.
    ///
    /// # Errors
    ///
    /// [`RenderError::Message`] when the value does not format.
    fn render(
        &self,
        compiled: &[u8],
        input: &Input<'_>,
        sink: &mut dyn Sink,
    ) -> Result<(), RenderError>;
    /// The keys the value matches, best first, by the function's matching rules; an empty list
    /// leaves the catch-all. Each key is one `keys` yields.
    ///
    /// # Errors
    ///
    /// [`RenderError::Message`] when the value selects no variant.
    fn select<'k>(
        &self,
        compiled: &[u8],
        input: &Input<'_>,
        keys: VariantKeys<'k>,
    ) -> Result<Vec<VariantKey<'k>>, RenderError>;
}

/// A selector's variant keys, in NFC, each once.
#[cfg(feature = "render")]
#[derive(Debug, Clone, Copy)]
pub struct VariantKeys<'k>(&'k [String]);

/// One key of a selection's [`VariantKeys`]: only they yield one.
#[cfg(feature = "render")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VariantKey<'k> {
    index: usize,
    keys: PhantomData<&'k ()>,
}

#[cfg(feature = "render")]
impl<'k> VariantKeys<'k> {
    pub(crate) const fn new(keys: &'k [String]) -> Self {
        Self(keys)
    }

    /// Each key, with its text.
    pub fn iter(&self) -> impl Iterator<Item = (VariantKey<'k>, &'k str)> + use<'k> {
        self.0.iter().enumerate().map(|(index, key)| {
            (
                VariantKey {
                    index,
                    keys: PhantomData,
                },
                key.as_str(),
            )
        })
    }
}

#[cfg(feature = "render")]
impl VariantKey<'_> {
    /// Its position among its selector's keys.
    pub(crate) const fn index(self) -> usize {
        self.index
    }
}

/// The format modules' render halves a build registers, `:string`'s included. Only
/// [`Formats::new`] makes one.
#[cfg(feature = "render")]
pub struct Formats {
    renderers: Vec<&'static dyn FormatRenderer>,
}

#[cfg(feature = "render")]
impl Formats {
    /// The build's render halves beside `:string`'s.
    ///
    /// # Errors
    ///
    /// [`RenderError::Registered`] when two share a [`FormatId`].
    pub fn new(renderers: &[&'static dyn FormatRenderer]) -> Result<Self, RenderError> {
        let mut held: Vec<&'static dyn FormatRenderer> = vec![&crate::string::STRING];
        for &renderer in renderers {
            if held.iter().any(|earlier| earlier.id() == renderer.id()) {
                return Err(RenderError::Registered(renderer.id()));
            }
            held.push(renderer);
        }
        Ok(Self { renderers: held })
    }

    /// The render half of the format module whose identity is `id`.
    pub(crate) fn get(&self, id: &str) -> Option<&'static dyn FormatRenderer> {
        self.renderers
            .iter()
            .copied()
            .find(|renderer| renderer.id().as_str() == id)
    }
}
