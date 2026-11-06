//! Why a module does not load, why a package or a text is refused, and why a presentation has no
//! language.

#[cfg(feature = "render")]
use std::fmt;

#[cfg(feature = "render")]
use siros_explain::{IntoArg, MessageId, ModuleId, kind};

#[cfg(feature = "render")]
use crate::form::BareKind;
#[cfg(feature = "render")]
use crate::format::FormatId;
#[cfg(feature = "render")]
use crate::locale::LocaleTag;
#[cfg(feature = "render")]
use crate::package::{CredentialName, TransactionKind, module_name};
#[cfg(feature = "render")]
use crate::render::RendererVersion;

/// Why a module was refused when it loaded.
#[cfg(feature = "load")]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, siros_explain::Explain)]
#[explain(domain = "i18n.module")]
pub enum ModuleError {
    /// A source breaks the resource format.
    #[error("the module's source {source_index}, line {line}: {rule}")]
    Resource {
        /// The source's index among the sources given.
        source_index: usize,
        /// The line, from 1.
        line: usize,
        /// The rule the line breaks.
        rule: ResourceRule,
    },
    /// A locale's source is given twice.
    #[error("the module's source for {0} is given twice")]
    Locale(#[explain(name = "locale")] LocaleTag),
    /// The declaration holds a message outside the module's domain.
    #[error("the declared message {0} lies outside the module's domain")]
    Outside(#[explain(name = "message")] String),
    /// The declaration holds two different messages under one identifier.
    #[error("the declaration of {0} holds two messages")]
    Declaration(#[explain(name = "message")] String),
    /// A source gives a key twice.
    #[error("{key} is given twice in {locale}")]
    Repeated {
        /// The key.
        key: String,
        /// The locale.
        locale: LocaleTag,
    },
    /// A key lacks a message in a locale the module supports.
    #[error("{key} has no message in {locale}")]
    Missing {
        /// The key.
        key: String,
        /// The locale.
        locale: LocaleTag,
    },
    /// A source gives a message for a key the declaration lacks.
    #[error("{key} in {locale} is no key of the declaration")]
    Undeclared {
        /// The key.
        key: String,
        /// The locale.
        locale: LocaleTag,
    },
    /// A message is no MF2 message.
    #[error("{key} in {locale} is no MessageFormat 2 message: byte {at}")]
    Syntax {
        /// The key.
        key: String,
        /// The locale.
        locale: LocaleTag,
        /// The offset, in bytes, where the grammar fails.
        at: usize,
    },
    /// A message breaks a rule of MF2's data model.
    #[error("{key} in {locale} is no valid MessageFormat 2 message: {rule}")]
    Invalid {
        /// The key.
        key: String,
        /// The locale.
        locale: LocaleTag,
        /// The rule.
        rule: Validity,
    },
    /// A message names an argument its key does not declare.
    #[error("{key} in {locale} names {argument}, which its key does not declare")]
    Argument {
        /// The key.
        key: String,
        /// The locale.
        locale: LocaleTag,
        /// The argument.
        argument: String,
    },
    /// A placeholder calls a function no registered format module provides.
    #[error("{key} in {locale} calls :{function}, which no registered format module provides")]
    Function {
        /// The key.
        key: String,
        /// The locale.
        locale: LocaleTag,
        /// The function.
        function: String,
    },
    /// A function refuses its operand, its options, or its use.
    #[error("{key} in {locale} calls {{{call}}}: {refusal}")]
    Kind {
        /// The key.
        key: String,
        /// The locale.
        locale: LocaleTag,
        /// The call: its operand as written, when it has one, and its function, the implicit one
        /// included: `$name :number`, `|literal| :string`, `:number`.
        call: String,
        /// What the function refuses.
        refusal: Refusal,
    },
    /// A registered format module refuses the main module's format of a bare value.
    #[error("{locale} formats no bare {kind} through :{function}: {refusal}")]
    Bare {
        /// The value's kind.
        kind: BareKind,
        /// The locale.
        locale: LocaleTag,
        /// The function its kind calls.
        function: &'static str,
        /// What the function refuses.
        refusal: Refusal,
    },
    /// Markup names a style the renderer does not apply.
    #[error("{key} in {locale} names the markup {markup}")]
    Markup {
        /// The key.
        key: String,
        /// The locale.
        locale: LocaleTag,
        /// The markup's name.
        markup: String,
    },
    /// Markup carries options, which no style takes.
    #[error("{key} in {locale} gives the markup {markup} options")]
    MarkupOption {
        /// The key.
        key: String,
        /// The locale.
        locale: LocaleTag,
        /// The markup's name.
        markup: String,
    },
    /// Markup leaves a style unbalanced: a close without its open, an open never closed, a close
    /// across another open style, a style opened inside itself, or a standalone style.
    #[error("{key} in {locale} leaves the markup {markup} unbalanced")]
    Nesting {
        /// The key.
        key: String,
        /// The locale.
        locale: LocaleTag,
        /// The markup's name.
        markup: String,
    },
    /// A source defines options of a format the module's messages do not call.
    #[error("{locale} defines options of {format}, which the module's messages do not call")]
    Format {
        /// The format.
        format: String,
        /// The locale.
        locale: LocaleTag,
    },
    /// A source defines an option its format does not take.
    #[error("{locale} defines {option} of {format}, which the format does not take")]
    UnknownOption {
        /// The format.
        format: String,
        /// The option.
        option: String,
        /// The locale.
        locale: LocaleTag,
    },
    /// The module lacks an option of a format it uses, for a language it supports.
    #[error("the module defines no {option} of {format} for {locale}")]
    Option {
        /// The format.
        format: FormatId,
        /// The option.
        option: &'static str,
        /// The language.
        locale: LocaleTag,
    },
    /// A format module refuses an option's text.
    #[error("{option} of {format} for {locale} is no valid value: {text}")]
    OptionText {
        /// The format.
        format: FormatId,
        /// The option.
        option: &'static str,
        /// The language.
        locale: LocaleTag,
        /// The text as written.
        text: String,
    },
    /// A format module reads an option its `options` do not name.
    #[error("{format} reads {option}, which its options do not name")]
    UndeclaredOption {
        /// The format.
        format: FormatId,
        /// The option.
        option: &'static str,
    },
    /// Two registered format modules share an identity or a function.
    #[error("two registered format modules provide {0}")]
    Compiler(#[explain(name = "name")] &'static str),
    /// A registered format module lists an option twice.
    #[error("the format module {format} lists its option {option} twice")]
    Listed {
        /// The format.
        format: FormatId,
        /// The option.
        option: &'static str,
    },
}

/// The resource format's rules (W3C i18n-discuss's message resource syntax).
#[cfg(feature = "load")]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, siros_explain::Explain)]
#[explain(domain = "i18n.resource")]
pub enum ResourceRule {
    /// The line is no line of the grammar.
    #[error("the line is no comment, metadata, frontmatter, section head or entry")]
    Line,
    /// A backslash starts no escape of the resource format.
    #[error("a backslash starts no escape")]
    Escape,
    /// The frontmatter is missing or given twice.
    #[error("the resource has no frontmatter or two")]
    Frontmatter,
    /// A section head or an entry comes before the frontmatter.
    #[error("a section head or an entry comes before the frontmatter")]
    Order,
    /// Metadata other than the resource's locale.
    #[error("the metadata {name} is no metadata of a module")]
    Metadata {
        /// The metadata's name.
        name: String,
    },
    /// The resource names no locale, or two.
    #[error("the resource names no locale before its frontmatter, or two")]
    NoLocale,
    /// The locale is no language tag.
    #[error("{tag} is no language tag")]
    Tag {
        /// The text.
        tag: String,
    },
    /// The direction is neither `ltr` nor `rtl`.
    #[error("the direction {direction} is neither ltr nor rtl")]
    Direction {
        /// The text.
        direction: String,
    },
}

/// MF2's data model rules (MessageFormat 2, errors.md "Data Model Errors").
#[cfg(feature = "load")]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, siros_explain::Explain)]
#[explain(domain = "i18n.validity")]
pub enum Validity {
    /// A variant's keys are not as many as the selectors.
    #[error("Variant Key Mismatch")]
    VariantKeyMismatch,
    /// No variant has only catch-all keys.
    #[error("Missing Fallback Variant")]
    MissingFallbackVariant,
    /// A selector references no declaration with a function.
    #[error("Missing Selector Annotation: ${variable}")]
    MissingSelectorAnnotation {
        /// The selector.
        variable: String,
    },
    /// A variable is declared twice, or after a declaration names it.
    #[error("Duplicate Declaration: ${variable}")]
    DuplicateDeclaration {
        /// The variable.
        variable: String,
    },
    /// An expression or markup names an option twice.
    #[error("Duplicate Option Name: {option}")]
    DuplicateOptionName {
        /// The option.
        option: String,
    },
    /// Two variants have the same keys.
    #[error("Duplicate Variant")]
    DuplicateVariant,
}

/// What a function refuses in a placeholder or a declaration, as its format module's load half
/// reports it.
#[cfg(feature = "load")]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, siros_explain::Explain)]
#[explain(domain = "i18n.refusal")]
pub enum Refusal {
    /// The operand: its kind, its literal, or its absence (MF2's Bad Operand).
    #[error("the function refuses its operand")]
    Operand,
    /// An option or its value (MF2's Bad Option).
    #[error("the function refuses its option {option}")]
    Option {
        /// The option.
        option: String,
    },
    /// The use as a selector (MF2's Bad Selector).
    #[error("the function's value selects no variant")]
    Selector,
    /// The use in a placeholder.
    #[error("the function's value does not format")]
    Formatter,
}

/// A format module's refusal of one language's option: of its text, which the loader reports as
/// [`ModuleError::OptionText`], or of an option outside the format's `options`, reported as
/// [`ModuleError::UndeclaredOption`]. Only [`FormatOption::refuse`](crate::FormatOption::refuse)
/// and [`LanguageFormats::require`](crate::LanguageFormats::require) make one.
#[cfg(feature = "load")]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, siros_explain::Explain)]
#[explain(domain = "i18n.format")]
#[error("the format refuses {option}")]
pub struct RefusedOption {
    option: &'static str,
    #[explain(skip)]
    cause: OptionRefusal,
}

/// Why a format module refuses an option.
#[cfg(feature = "load")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionRefusal {
    /// The format refuses the option's text, given as the module writes it.
    Text(String),
    /// The format reads an option its `options` do not name.
    Undeclared,
}

#[cfg(feature = "load")]
impl RefusedOption {
    pub(crate) fn new(option: &'static str, text: &str) -> Self {
        Self {
            option,
            cause: OptionRefusal::Text(text.to_owned()),
        }
    }

    pub(crate) const fn undeclared(option: &'static str) -> Self {
        Self {
            option,
            cause: OptionRefusal::Undeclared,
        }
    }

    /// The option.
    #[must_use]
    pub const fn option(&self) -> &'static str {
        self.option
    }

    /// Why the format refuses it.
    #[must_use]
    pub const fn cause(&self) -> &OptionRefusal {
        &self.cause
    }
}

/// An MF2 formatting error a format module reports (MessageFormat 2, errors.md "Message Function
/// Errors").
#[cfg(feature = "render")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatFailure {
    /// `bad-operand`: the value is no operand of the function.
    BadOperand,
    /// `bad-selector`: the function's value selects no variant.
    BadSelector,
    /// `bad-variant-key`: a variant key is no key of the function.
    BadVariantKey,
}

#[cfg(feature = "render")]
impl FormatFailure {
    /// The error's name in MF2's errors.md.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BadOperand => "bad-operand",
            Self::BadSelector => "bad-selector",
            Self::BadVariantKey => "bad-variant-key",
        }
    }
}

#[cfg(feature = "render")]
impl std::fmt::Display for FormatFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(feature = "render")]
impl IntoArg for FormatFailure {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.name()
    }
}

/// Why a text did not render. No fallback text reaches the End-User: the screen or the matcher's
/// entries that needed the text are not shown.
#[cfg(feature = "render")]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, siros_explain::Explain)]
#[explain(domain = "i18n.render")]
pub enum RenderError {
    /// The query names a message no module of the package holds: its module is absent, or its
    /// module lacks its key.
    #[error("the query names no message of the package's modules")]
    Unknown,
    /// The text draws from a module of the package that the screen does not hold.
    #[error("the text draws from the module {module}, which the screen does not hold")]
    Outside {
        /// The module.
        module: String,
    },
    /// A compiled placeholder names a format module the build does not register.
    #[error("the build registers no format module {0}")]
    Format(#[explain(name = "format")] String),
    /// A format module reported an MF2 formatting error.
    #[error("the message does not format: {0}")]
    Message(#[explain(name = "kind")] FormatFailure),
    /// A query's arguments differ from its message's declaration: a name the message does not
    /// declare, a declared name left out, or a value of another kind.
    #[error("the query's arguments are not its message's")]
    Arguments,
    /// A placeholder or a selector names an optional argument the query leaves out.
    #[error("the message shows {argument}, which the query leaves out")]
    AbsentArgument {
        /// The argument.
        argument: String,
    },
    /// The text is an optional value the input left out.
    #[error("the text is a value the input left out")]
    Absent,
    /// A bare value or list, and no main module of the package compiles its kind's format.
    #[error("no main module of the package formats a bare {kind}")]
    Bare {
        /// The kind.
        kind: BareKind,
    },
    /// Two registered render halves share an identity.
    #[error("the build registers the format module {0} twice")]
    Registered(#[explain(name = "format")] FormatId),
    /// A compiled placeholder's bytes do not read as its format module writes them.
    #[error("a compiled placeholder of the format module {0} is malformed")]
    Compiled(#[explain(name = "format")] FormatId),
    /// The package refused an entry the text needs.
    #[error(transparent)]
    Package(#[from] PackageError),
}

/// Why a package, or a step that reads or builds one, was refused.
#[cfg(feature = "render")]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, siros_explain::Explain)]
#[explain(domain = "i18n.package")]
pub enum PackageError {
    /// The bytes name another format version, or none.
    #[error("the bytes are no package of this format version")]
    Version,
    /// The header's root differs from the root the reader was given.
    #[error("the package's root is not the root it was read under")]
    Root,
    /// An entry does not match the root through its audit path.
    #[error("the package's entry {entry} does not match its root")]
    Integrity {
        /// The entry's index.
        entry: usize,
    },
    /// An entry or a node of its audit path lies outside the package's bytes.
    #[error("the package's entry {entry} or its audit path lies outside its bytes")]
    Bounds {
        /// The entry's index.
        entry: usize,
    },
    /// An entry matches the root and does not read as the format writes it.
    #[error("the package's entry {entry} matches its root and is malformed")]
    Malformed {
        /// The entry's index.
        entry: usize,
    },
    /// Another version of the renderer built the package, so its precomputed texts are another
    /// renderer's.
    #[error("the package was built by renderer {built}")]
    Renderer {
        /// The version that built it.
        built: RendererVersion,
    },
    /// The package holds no module of this identity.
    #[error("the package holds no module {0}")]
    Module(#[explain(name = "module")] ModuleName),
    /// A package builder given a locale twice.
    #[error("the locale {0} is given twice")]
    RepeatedLocale(#[explain(name = "locale")] LocaleTag),
    /// A package builder or a screen given a module twice.
    #[error("the module {0} is given twice")]
    RepeatedModule(#[explain(name = "module")] ModuleName),
    /// A package builder given a module's key twice.
    #[error("the key {key} of the module {module} is given twice")]
    RepeatedKey {
        /// The module.
        module: ModuleName,
        /// The key.
        key: MessageId,
    },
    /// A key the module does not hold.
    #[error("the module {module} holds no key {key}")]
    Key {
        /// The module.
        module: ModuleName,
        /// The key.
        key: MessageId,
    },
    /// The bytes run past the package's last entry or end before it.
    #[error("the package's bytes do not end where its last entry ends")]
    Length,
    /// A package builder given no locale.
    #[error("the package names no locale")]
    NoLocale,
    /// A registration's builder given a credential twice.
    #[error("the credential {0} is given twice")]
    RepeatedCredential(#[explain(name = "credential")] CredentialName),
    /// A registration's builder given a transaction type twice.
    #[error("the transaction type {0} is given twice")]
    RepeatedTransaction(#[explain(name = "transaction")] TransactionKind),
}

/// Why a presentation has no language.
#[cfg(feature = "render")]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, siros_explain::Explain)]
#[explain(domain = "i18n.language")]
pub enum NoLanguage {
    /// No tag of the priority list serves every module, and a module, the one named, enforces
    /// understood languages.
    #[error(
        "no language the End-User understands serves every module, and the module {0} requires one"
    )]
    NotUnderstood(#[explain(name = "module")] ModuleName),
    /// No tag of the app's fallback list serves every module, or the list is empty.
    #[error("no fallback language serves every module of the presentation")]
    NoFallback,
    /// The module a profile selected a locale for holds no entry of that locale.
    #[error("the module {module} holds no entry of {locale}, which its profile selected")]
    Selected {
        /// The module.
        module: ModuleName,
        /// The locale.
        locale: LocaleTag,
    },
}

#[cfg(feature = "render")]
impl NoLanguage {
    /// A selected module lacking its locale.
    pub(crate) fn selected(selected: &crate::screen::Selected) -> Self {
        Self::Selected {
            module: ModuleName::of(selected.module()),
            locale: selected.locale().clone(),
        }
    }
}

/// A module by its identity and its name: `main`, a crate's domain, or a defined module's plug-in
/// and digest in hexadecimal.
#[cfg(feature = "render")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleName {
    id: ModuleId,
    name: String,
}

#[cfg(feature = "render")]
impl ModuleName {
    /// The name of `id`.
    #[must_use]
    pub fn of(id: ModuleId) -> Self {
        Self {
            id,
            name: module_name(id),
        }
    }

    /// The module's identity.
    #[must_use]
    pub const fn id(&self) -> ModuleId {
        self.id
    }
}

#[cfg(feature = "render")]
impl fmt::Display for ModuleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

#[cfg(feature = "render")]
impl IntoArg for ModuleName {
    type Kind = kind::Raw;

    fn arg(&self) -> &str {
        &self.name
    }
}
