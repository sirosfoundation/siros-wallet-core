//! Why a module does not load, why a message does not resolve, and why a context fails its
//! check.

use std::fmt;

use siros_explain::Explain;

use crate::locale::LocaleTag;

/// Why [`Context::module`](crate::Context::module) refused a module: the first rule it breaks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum LoadError {
    /// The module breaks a rule of the resource format, of MessageFormat 2's syntax or data
    /// model, or of the markup the engine styles.
    #[error("line {line}: {rule}")]
    #[explain(id = "load.syntax")]
    Syntax {
        /// The line, from 1, where the construct that breaks the rule starts.
        line: usize,
        /// The rule.
        #[source]
        rule: SyntaxRule,
    },
    /// The module words an id the context or the module already words.
    #[error("{id} is given twice")]
    #[explain(id = "load.repeated")]
    Repeated {
        /// The id.
        id: String,
    },
    /// The module's `@locale` is absent, or differs from the context's.
    #[error("the module's locale {} differs from the context's {}", Shown(.locale.as_ref()), Shown(.context.as_ref()))]
    #[explain(id = "load.locale")]
    Locale {
        /// The module's locale; `None` when it names none.
        locale: Option<LocaleTag>,
        /// The context's locale; `None` before its first module.
        context: Option<LocaleTag>,
    },
    /// A message calls a function no formatter of the context defines.
    #[error("{id} calls :{function}, which no formatter defines")]
    #[explain(id = "load.function")]
    Function {
        /// The message's id.
        id: String,
        /// The function, without its colon.
        function: String,
    },
    /// A section whose settings its formatter refuses.
    #[error("[{section}]: {rule}")]
    #[explain(id = "load.format")]
    Format {
        /// The section's name.
        section: String,
        /// The rule.
        #[source]
        rule: FormatRule,
    },
    /// A message's call its function refuses when the module loads: MessageFormat 2's message
    /// function errors.
    #[error("{id} calls :{function}: {refusal}")]
    #[explain(id = "load.call")]
    Call {
        /// The message's id.
        id: String,
        /// The function that refuses, without its colon.
        function: String,
        /// What it refuses.
        #[source]
        refusal: Refusal,
    },
}

/// Why a message does not load, before its id and its line join it: [`Fault::at`] makes the
/// [`LoadError`].
#[derive(Debug)]
pub(crate) enum Fault {
    /// The byte offset where the message leaves MF2's grammar.
    Syntax(usize),
    /// Variant Key Mismatch.
    VariantKeyMismatch,
    /// Missing Fallback Variant.
    MissingFallbackVariant,
    /// Missing Selector Annotation, of this variable.
    MissingSelectorAnnotation(String),
    /// Duplicate Declaration, of this variable.
    DuplicateDeclaration(String),
    /// Duplicate Option Name, of this option.
    DuplicateOptionName(String),
    /// Duplicate Variant.
    DuplicateVariant,
    /// Markup of this name, which names no style.
    Markup(String),
    /// Markup of this name with options.
    MarkupOption(String),
    /// Markup of this name, which leaves the nested order.
    Nesting(String),
    /// A function of this name, which no formatter defines.
    Function(String),
    /// The refusal of a call by its function, of this name.
    Call(String, Refusal),
}

impl Fault {
    /// The error of the fault in the message `id`, which starts at `line`.
    pub(crate) fn at(self, id: &str, line: usize) -> LoadError {
        let id = id.to_owned();
        let rule = match self {
            Self::Syntax(at) => SyntaxRule::Message { id, at },
            Self::VariantKeyMismatch => SyntaxRule::VariantKeyMismatch { id },
            Self::MissingFallbackVariant => SyntaxRule::MissingFallbackVariant { id },
            Self::MissingSelectorAnnotation(variable) => {
                SyntaxRule::MissingSelectorAnnotation { id, variable }
            }
            Self::DuplicateDeclaration(variable) => {
                SyntaxRule::DuplicateDeclaration { id, variable }
            }
            Self::DuplicateOptionName(option) => SyntaxRule::DuplicateOptionName { id, option },
            Self::DuplicateVariant => SyntaxRule::DuplicateVariant { id },
            Self::Markup(markup) => SyntaxRule::Markup { id, markup },
            Self::MarkupOption(markup) => SyntaxRule::MarkupOption { id, markup },
            Self::Nesting(markup) => SyntaxRule::Nesting { id, markup },
            Self::Function(function) => return LoadError::Function { id, function },
            Self::Call(function, refusal) => {
                return LoadError::Call {
                    id,
                    function,
                    refusal,
                };
            }
        };
        LoadError::Syntax { line, rule }
    }
}

/// The rules of syntax a module follows: the resource format's (the W3C i18n-discuss message
/// resource syntax), MessageFormat 2's syntax and data model (spec/errors.md "Syntax Errors",
/// "Data Model Errors"), and the markup the engine styles.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum SyntaxRule {
    /// The line is no comment, metadata, frontmatter, section head or entry, or holds a
    /// character a line takes only escaped.
    #[error("the line is no comment, metadata, frontmatter, section head or entry")]
    #[explain(id = "syntax.line")]
    Line,
    /// A backslash starts no escape of the resource format.
    #[error("a backslash starts no escape")]
    #[explain(id = "syntax.escape")]
    Escape,
    /// The frontmatter `---` is missing or given twice.
    #[error("the resource has no frontmatter, or two")]
    #[explain(id = "syntax.frontmatter")]
    Frontmatter,
    /// A section head or an entry comes before the frontmatter.
    #[error("a section head or an entry comes before the frontmatter")]
    #[explain(id = "syntax.order")]
    Order,
    /// Metadata other than one `@locale` and one `@dir` before the frontmatter.
    #[error("the metadata {name} is no metadata of a module")]
    #[explain(id = "syntax.metadata")]
    Metadata {
        /// The metadata's name.
        name: String,
    },
    /// The locale is no language tag.
    #[error("{tag} is no language tag")]
    #[explain(id = "syntax.tag")]
    Tag {
        /// The text.
        tag: String,
    },
    /// The direction is neither `ltr` nor `rtl`.
    #[error("the direction {direction} is neither ltr nor rtl")]
    #[explain(id = "syntax.direction")]
    Direction {
        /// The text.
        direction: String,
    },
    /// A message leaves MessageFormat 2's syntax.
    #[error("the message {id} leaves MessageFormat 2's syntax at byte {at}")]
    #[explain(id = "syntax.message")]
    Message {
        /// The message's id.
        id: String,
        /// The offset, in bytes of the message, where the grammar fails.
        at: usize,
    },
    /// A variant's keys are not as many as the selectors.
    #[error("Variant Key Mismatch in {id}")]
    #[explain(id = "syntax.variant_key_mismatch")]
    VariantKeyMismatch {
        /// The message's id.
        id: String,
    },
    /// No variant has only catch-all keys.
    #[error("Missing Fallback Variant in {id}")]
    #[explain(id = "syntax.missing_fallback_variant")]
    MissingFallbackVariant {
        /// The message's id.
        id: String,
    },
    /// A selector references, directly or through local declarations, a literal without a
    /// function.
    #[error("Missing Selector Annotation in {id}: ${variable}")]
    #[explain(id = "syntax.missing_selector_annotation")]
    MissingSelectorAnnotation {
        /// The message's id.
        id: String,
        /// The selector.
        variable: String,
    },
    /// A variable is declared twice, or after a declaration names it.
    #[error("Duplicate Declaration in {id}: ${variable}")]
    #[explain(id = "syntax.duplicate_declaration")]
    DuplicateDeclaration {
        /// The message's id.
        id: String,
        /// The variable.
        variable: String,
    },
    /// An expression or markup names an option twice.
    #[error("Duplicate Option Name in {id}: {option}")]
    #[explain(id = "syntax.duplicate_option_name")]
    DuplicateOptionName {
        /// The message's id.
        id: String,
        /// The option.
        option: String,
    },
    /// Two variants have the same keys.
    #[error("Duplicate Variant in {id}")]
    #[explain(id = "syntax.duplicate_variant")]
    DuplicateVariant {
        /// The message's id.
        id: String,
    },
    /// Markup names a style the engine does not apply.
    #[error("{id} names the markup {markup}")]
    #[explain(id = "syntax.markup")]
    Markup {
        /// The message's id.
        id: String,
        /// The markup's name.
        markup: String,
    },
    /// Markup carries options, which no style takes.
    #[error("{id} gives the markup {markup} options")]
    #[explain(id = "syntax.markup_option")]
    MarkupOption {
        /// The message's id.
        id: String,
        /// The markup's name.
        markup: String,
    },
    /// Markup does not nest: a close without its open, an open never closed, a close across
    /// another open style, a style opened inside itself, or a standalone style.
    #[error("{id} leaves the markup {markup} unbalanced")]
    #[explain(id = "syntax.nesting")]
    Nesting {
        /// The message's id.
        id: String,
        /// The markup's name.
        markup: String,
    },
}

/// Why a formatter refuses the settings of a section it reads.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum FormatRule {
    /// The section, or a setting of it, is given twice.
    #[error("{key} is given twice")]
    #[explain(id = "format.repeated")]
    Repeated {
        /// The setting's key; the section's name for the section.
        key: String,
    },
    /// The section gives a setting the formatter does not take.
    #[error("the formatter takes no setting {key}")]
    #[explain(id = "format.undefined")]
    Undefined {
        /// The setting's key.
        key: String,
    },
    /// The section lacks a setting the formatter reads.
    #[error("the section lacks the setting {key}")]
    #[explain(id = "format.missing")]
    Missing {
        /// The setting's key.
        key: String,
    },
    /// A setting's text is outside the formatter's grammar for it.
    #[error("the setting {key} is no valid value")]
    #[explain(id = "format.text")]
    Text {
        /// The setting's key.
        key: String,
    },
    /// A setting names something no setting the formatter holds defines.
    #[error("the setting {key} names {name}, which no setting defines")]
    #[explain(id = "format.unknown")]
    Unknown {
        /// The setting's key.
        key: String,
        /// What it names.
        name: String,
    },
}

/// What a function refuses in a call (MessageFormat 2, spec/errors.md "Message Function
/// Errors").
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum Refusal {
    /// The operand: its absence, or a literal the function does not read (Bad Operand).
    #[error("the function refuses its operand")]
    #[explain(id = "refusal.operand")]
    Operand,
    /// An option, its value, or a variable given for it (Bad Option).
    #[error("the function refuses its option {option}")]
    #[explain(id = "refusal.option")]
    Option {
        /// The option.
        option: String,
    },
    /// A variant key the function's selection does not read (Bad Variant Key).
    #[error("the function's selection reads no key {key}")]
    #[explain(id = "refusal.key")]
    Key {
        /// The key.
        key: String,
    },
    /// The use as a selector (Bad Selector).
    #[error("the function's value selects no variant")]
    #[explain(id = "refusal.selector")]
    Selector,
}

/// Why [`Context::resolve`](crate::Context::resolve) refused a message. No fallback text reaches
/// the End-User.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum ResolveError {
    /// No module of the context words the id.
    #[error("no module words {id}")]
    #[explain(id = "resolve.unknown")]
    Unknown {
        /// The message's id.
        id: String,
    },
    /// The message's wording reads an argument the message does not give.
    #[error("{id} reads the argument {key}, which the message does not give")]
    #[explain(id = "resolve.unresolved")]
    Unresolved {
        /// The message's id.
        id: String,
        /// The argument's key.
        key: String,
    },
    /// A function refuses its operand: a value it takes no form of, or a literal it does not
    /// read.
    #[error("{id}: :{function} refuses its operand")]
    #[explain(id = "resolve.operand")]
    Operand {
        /// The message's id.
        id: String,
        /// The function, without its colon.
        function: String,
    },
    /// A function refuses an option's value, which a variable gives (an argument's text, or a
    /// declared call's value), or a value with that option.
    #[error("{id}: :{function} refuses its option {option}")]
    #[explain(id = "resolve.option")]
    Option {
        /// The message's id.
        id: String,
        /// The function, without its colon.
        function: String,
        /// The option.
        option: String,
    },
    /// A call names a function that takes no value of its argument's type.
    #[error("{id}: the argument {key} takes no :{function}")]
    #[explain(id = "resolve.unformatted")]
    Unformatted {
        /// The message's id.
        id: String,
        /// The argument's key.
        key: String,
        /// The function, without its colon.
        function: String,
    },
    /// The default function of a selector's argument type refuses the selector or one of its
    /// variant keys.
    #[error("{id}: :{function} refuses the selector: {refusal}")]
    #[explain(id = "resolve.selector")]
    Selector {
        /// The message's id.
        id: String,
        /// The function, without its colon.
        function: String,
        /// The refusal: [`Refusal::Selector`] or [`Refusal::Key`].
        #[source]
        refusal: Refusal,
    },
    /// The message gives a value whose `Display` fails.
    #[error("{id} gives the argument {key} a value that does not display")]
    #[explain(id = "resolve.argument")]
    Argument {
        /// The message's id.
        id: String,
        /// The argument's key, as the wording spells it.
        key: String,
    },
}

/// Why `Context::check` failed: the first of its rules a row breaks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum CheckError {
    /// Two rows share an id: two crates chose one scope.
    #[error("two rows declare {id}")]
    #[explain(id = "check.repeated")]
    Repeated {
        /// The id.
        id: String,
    },
    /// No module of the context words a row's id.
    #[error("no module words {id}")]
    #[explain(id = "check.unworded")]
    Unworded {
        /// The id.
        id: String,
    },
    /// A message's wording names an argument its row lacks.
    #[error("the wording of {id} names {key}, which its row lacks")]
    #[explain(id = "check.unknown")]
    Unknown {
        /// The id.
        id: String,
        /// The argument's key.
        key: String,
    },
}

/// A locale an error names, or `none`.
struct Shown<'a>(Option<&'a LocaleTag>);

impl fmt::Display for Shown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(locale) => locale.fmt(f),
            None => f.write_str("none"),
        }
    }
}
