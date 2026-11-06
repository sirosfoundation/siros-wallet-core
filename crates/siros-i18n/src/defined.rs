//! Defined modules in their render form, written by the plug-in that converts their metadata with
//! no loader: each locale's messages as literal text, styles, arguments and selections over
//! `:string` keys, each typed argument formatted as the main module formats a bare value of its
//! kind in that locale. The matcher converts metadata that arrives with a request into one and
//! renders through it beside its package ([`Screen::carrying`](crate::Screen::carrying)); the
//! wallet adds one to the packages it builds.

use std::borrow::Cow;

use sha2::{Digest as _, Sha256};
use siros_explain::{ArgKind, DefinedKey, DefinedModule, Explain, Keyed, ParamKind};

use crate::bytes::Writer;
use crate::form::{
    BareCalls, BareKind, BodyForm, CompiledCall, Dir, Expression, KeyRef, LanguagePolicy,
    MessageForm, ParamForm, ParamName, PartForm, Root, SelectorForm, VariantForm,
};
use crate::format::Direction;
use crate::locale::LocaleTag;
use crate::package::{write_direction, write_message};
use crate::sink::Style;

/// The main module's entry of a locale: its tag, its direction, and its formats of bare values,
/// which a defined module's typed arguments in that locale take. A [`Package`](crate::Package)
/// and, under `load`, a loaded main module give them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainLocale {
    pub(crate) locale: LocaleTag,
    pub(crate) direction: Direction,
    pub(crate) bare: BareCalls,
}

impl MainLocale {
    /// The tag.
    #[must_use]
    pub const fn locale(&self) -> &LocaleTag {
        &self.locale
    }

    /// The direction its resource states.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }
}

/// A part of a defined message's pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    /// Literal text.
    Text(String),
    /// Markup opening a style.
    Open(Style),
    /// Markup closing the innermost open style, which it names.
    Close(Style),
    /// An argument of the message's declaration, formatted by its kind: a text as given, a typed
    /// value as the main module formats a bare value of its kind in the locale.
    Argument(Cow<'static, str>),
}

/// A variant of a selection: one key per selector, `None` the catch-all, and its pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variant {
    /// The keys, one per selector; each an ASCII text, which NFC leaves as it is.
    pub keys: Vec<Option<&'static str>>,
    /// The pattern.
    pub pattern: Vec<Part>,
}

/// A defined message's body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// One pattern.
    Pattern(Vec<Part>),
    /// A selection over text arguments by `:string`, which takes the variant whose keys equal
    /// their texts (MF2's pattern selection), the variant of catch-alls alone the fallback.
    Select {
        /// The arguments selected on, each of a text kind.
        selectors: Vec<Cow<'static, str>>,
        /// The variants, the last of catch-alls alone.
        variants: Vec<Variant>,
    },
}

/// Why a defined module's messages are no render form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "i18n.defined")]
pub enum DefinedError {
    /// A locale given twice.
    #[error("the locale {0} is given twice")]
    Locale(#[explain(name = "locale")] LocaleTag),
    /// A declaration's parameter name that is no tokens, the grammar of a [`DefinedKey`].
    #[error("{key} declares the parameter {name}, which is no tokens")]
    ParameterName {
        /// The key.
        key: String,
        /// The name.
        name: String,
    },
    /// A locale lacks a declared key.
    #[error("{key} has no message in {locale}")]
    Missing {
        /// The key.
        key: String,
        /// The locale.
        locale: LocaleTag,
    },
    /// A locale gives a key the declaration lacks.
    #[error("{key} in {locale} is no key of the declaration")]
    Undeclared {
        /// The key.
        key: String,
        /// The locale.
        locale: LocaleTag,
    },
    /// A message names an argument its declaration lacks.
    #[error("{key} names {argument}, which its key does not declare")]
    Argument {
        /// The key.
        key: String,
        /// The argument.
        argument: String,
    },
    /// A typed argument whose kind the locale's main entry formats no bare value of.
    #[error("{key} in {locale} formats {argument}, whose kind no main format of the locale takes")]
    Format {
        /// The key.
        key: String,
        /// The locale.
        locale: LocaleTag,
        /// The argument.
        argument: String,
    },
    /// A selector over an argument of a kind `:string` does not select on.
    #[error("{key} selects on {argument}, which is no text")]
    Selector {
        /// The key.
        key: String,
        /// The argument.
        argument: String,
    },
    /// A selection whose variants break MF2's data model: a key count other than the
    /// selectors', a key that is no ASCII text, two variants of the same keys, or no variant of
    /// catch-alls alone (`message.abnf`; Variant Key Mismatch, Duplicate Variant, Missing
    /// Fallback Variant).
    #[error("{0}'s variants break MF2's data model")]
    Variants(#[explain(name = "key")] String),
    /// Markup closing a style that is not the innermost open one, or a style left open.
    #[error("{0} leaves its markup unbalanced")]
    Markup(#[explain(name = "key")] String),
}

/// A defined module's messages in one locale, sorted by key, and its direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DefinedLocale {
    pub(crate) locale: LocaleTag,
    pub(crate) direction: Direction,
    pub(crate) messages: Vec<MessageForm>,
}

impl DefinedLocale {
    /// The message `key`.
    pub(crate) fn message(&self, key: &str) -> Option<&MessageForm> {
        let index = self
            .messages
            .binary_search_by(|form| form.id.as_str().cmp(key))
            .ok()?;
        self.messages.get(index)
    }

    /// The format modules its messages call, each once, sorted.
    pub(crate) fn formats(&self) -> Vec<String> {
        let mut formats: Vec<String> = self
            .messages
            .iter()
            .flat_map(|message| message.expressions.iter().map(|e| e.call.format.clone()))
            .collect();
        formats.sort();
        formats.dedup();
        formats
    }
}

/// A defined module in its render form: its identity, the SHA-256 of its locales' encoding, its
/// language policy, and each locale's messages. Only [`DefinedBuilder::finish`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinedForm {
    pub(crate) id: DefinedModule,
    pub(crate) digest: [u8; 32],
    pub(crate) policy: LanguagePolicy,
    pub(crate) locales: Vec<DefinedLocale>,
}

impl DefinedForm {
    /// A builder of the module `id` of these keys, each with its arguments and their kinds.
    #[must_use]
    pub const fn builder(
        id: DefinedModule,
        policy: LanguagePolicy,
        declaration: Keyed<DefinedKey, Keyed<Cow<'static, str>, ParamKind>>,
    ) -> DefinedBuilder {
        DefinedBuilder {
            id,
            policy,
            declaration,
            locales: Vec::new(),
        }
    }

    /// The identity.
    #[must_use]
    pub const fn id(&self) -> DefinedModule {
        self.id
    }

    /// The SHA-256 of its locales' encoding, which a record commits to.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The language policy.
    #[must_use]
    pub const fn policy(&self) -> LanguagePolicy {
        self.policy
    }

    /// The locales, in the order given.
    pub fn locales(&self) -> impl Iterator<Item = &LocaleTag> {
        self.locales.iter().map(|locale| &locale.locale)
    }
}

/// A defined module under construction: its declaration, and the locales given so far.
#[derive(Debug)]
pub struct DefinedBuilder {
    id: DefinedModule,
    policy: LanguagePolicy,
    declaration: Keyed<DefinedKey, Keyed<Cow<'static, str>, ParamKind>>,
    locales: Vec<DefinedLocale>,
}

/// The `:string` call over a text: no bytes, which compare the operand's text as given.
fn string_call() -> CompiledCall {
    CompiledCall {
        format: "string".to_owned(),
        bytes: Vec::new(),
    }
}

/// The kind of a bare value a typed argument formats as; `None` for a text's kind.
const fn bare_kind(kind: ArgKind) -> Option<BareKind> {
    match kind {
        ArgKind::Count => Some(BareKind::Count),
        ArgKind::Decimal => Some(BareKind::Decimal),
        ArgKind::Date => Some(BareKind::Date),
        ArgKind::Time => Some(BareKind::Time),
        ArgKind::DateTime => Some(BareKind::DateTime),
        ArgKind::Amount => Some(BareKind::Amount),
        ArgKind::Currency => Some(BareKind::Currency),
        ArgKind::List => Some(BareKind::List),
        ArgKind::Message | ArgKind::Name | ArgKind::Text | ArgKind::Raw => None,
    }
}

/// One message being compiled: its key, its parameters, the locale and the main entry its typed
/// arguments take their formats from, and its expressions so far.
struct Compiling<'c> {
    key: &'c str,
    params: &'c [ParamForm],
    locale: &'c LocaleTag,
    main: Option<&'c MainLocale>,
    expressions: Vec<Expression>,
}

impl Compiling<'_> {
    /// The index of the parameter `name`.
    fn argument(&self, name: &str) -> Result<usize, DefinedError> {
        self.params
            .iter()
            .position(|param| param.name.as_str() == name)
            .ok_or_else(|| DefinedError::Argument {
                key: self.key.to_owned(),
                argument: name.to_owned(),
            })
    }

    /// An expression formatting the parameter `name` by its kind.
    fn placeholder(&mut self, name: &str) -> Result<usize, DefinedError> {
        let index = self.argument(name)?;
        let kind = self
            .params
            .get(index)
            .map(|param| param.kind)
            .ok_or_else(|| DefinedError::Argument {
                key: self.key.to_owned(),
                argument: name.to_owned(),
            })?;
        let call = match bare_kind(kind) {
            None => string_call(),
            Some(bare) => self
                .main
                .and_then(|main| main.bare.get(bare))
                .cloned()
                .ok_or_else(|| DefinedError::Format {
                    key: self.key.to_owned(),
                    locale: self.locale.clone(),
                    argument: name.to_owned(),
                })?,
        };
        self.expressions.push(Expression {
            root: Root::Argument(index),
            call,
            dir: Dir::Inherit,
        });
        Ok(self.expressions.len() - 1)
    }

    /// An expression selecting on the text parameter `name` by `:string`.
    fn selector(&mut self, name: &str) -> Result<usize, DefinedError> {
        let index = self.argument(name)?;
        let text = self.params.get(index).is_some_and(|param| {
            matches!(
                param.kind,
                ArgKind::Name | ArgKind::Raw | ArgKind::Text | ArgKind::Message
            )
        });
        if !text {
            return Err(DefinedError::Selector {
                key: self.key.to_owned(),
                argument: name.to_owned(),
            });
        }
        self.expressions.push(Expression {
            root: Root::Argument(index),
            call: string_call(),
            dir: Dir::Inherit,
        });
        Ok(self.expressions.len() - 1)
    }

    /// A pattern's parts, its markup balanced.
    fn pattern(&mut self, parts: &[Part]) -> Result<Vec<PartForm>, DefinedError> {
        let mut open: Vec<Style> = Vec::new();
        let mut out = Vec::with_capacity(parts.len());
        for part in parts {
            out.push(match part {
                Part::Text(text) => PartForm::Text(text.clone()),
                Part::Open(style) => {
                    open.push(*style);
                    PartForm::Open(*style)
                }
                Part::Close(style) => {
                    if open.pop() != Some(*style) {
                        return Err(DefinedError::Markup(self.key.to_owned()));
                    }
                    PartForm::Close(*style)
                }
                Part::Argument(name) => PartForm::Expression(self.placeholder(name)?),
            });
        }
        if open.is_empty() {
            Ok(out)
        } else {
            Err(DefinedError::Markup(self.key.to_owned()))
        }
    }

    /// A selection's selectors and variants.
    fn select(
        &mut self,
        selectors: &[Cow<'static, str>],
        variants: &[Variant],
    ) -> Result<BodyForm, DefinedError> {
        let broken = || DefinedError::Variants(self.key.to_owned());
        let mut forms: Vec<SelectorForm> = Vec::with_capacity(selectors.len());
        for name in selectors {
            forms.push(SelectorForm {
                expression: self.selector(name)?,
                keys: Vec::new(),
            });
        }
        let mut compiled = Vec::with_capacity(variants.len());
        for (index, variant) in variants.iter().enumerate() {
            if variant.keys.len() != forms.len()
                || variant.keys.iter().flatten().any(|key| !key.is_ascii())
                || variants
                    .iter()
                    .take(index)
                    .any(|earlier| earlier.keys == variant.keys)
            {
                return Err(broken());
            }
            let mut keys = Vec::with_capacity(variant.keys.len());
            for (selector, key) in forms.iter_mut().zip(&variant.keys) {
                keys.push(match key {
                    None => KeyRef::CatchAll,
                    Some(key) => {
                        let at = match selector.keys.iter().position(|known| known == key) {
                            Some(at) => at,
                            None => {
                                selector.keys.push((*key).to_owned());
                                selector.keys.len() - 1
                            }
                        };
                        KeyRef::Key(at)
                    }
                });
            }
            compiled.push(VariantForm {
                keys,
                pattern: self.pattern(&variant.pattern)?,
            });
        }
        if !variants
            .iter()
            .any(|variant| variant.keys.iter().all(Option::is_none))
        {
            return Err(broken());
        }
        Ok(BodyForm::Select {
            selectors: forms,
            variants: compiled,
        })
    }
}

impl DefinedBuilder {
    /// Adds a locale: each declared key's body, typed arguments formatted as `main`, the main
    /// module's entry of the locale, formats a bare value of their kind; `None` for a locale no
    /// main entry serves, whose messages then format texts alone. The locale's direction is
    /// `main`'s, unknown without it.
    ///
    /// # Errors
    ///
    /// [`DefinedError`]: the locale is given twice; a declared parameter's name is no tokens; a
    /// declared key lacks a body or a body's key is undeclared; a body names an undeclared argument, formats a typed argument the main entry
    /// gives no format of, selects on an argument that is no text, breaks MF2's variant rules or
    /// leaves its markup unbalanced.
    pub fn locale(
        &mut self,
        locale: LocaleTag,
        main: Option<&MainLocale>,
        bodies: &Keyed<DefinedKey, Body>,
    ) -> Result<(), DefinedError> {
        if self.locales.iter().any(|known| known.locale == locale) {
            return Err(DefinedError::Locale(locale));
        }
        if let Some(undeclared) = bodies
            .entries()
            .iter()
            .find(|entry| self.declaration.get(entry.key()).is_none())
        {
            return Err(DefinedError::Undeclared {
                key: undeclared.key().as_str().to_owned(),
                locale,
            });
        }
        let mut messages = Vec::with_capacity(self.declaration.entries().len());
        for declared in self.declaration.entries() {
            let key = declared.key().as_str();
            let body = bodies
                .get(declared.key())
                .ok_or_else(|| DefinedError::Missing {
                    key: key.to_owned(),
                    locale: locale.clone(),
                })?;
            let params = declared
                .value()
                .entries()
                .iter()
                .map(|param| {
                    let name = param.key().clone().into_owned();
                    let parsed = DefinedKey::parse(name.clone()).ok_or_else(|| {
                        DefinedError::ParameterName {
                            key: key.to_owned(),
                            name,
                        }
                    })?;
                    Ok(ParamForm {
                        name: ParamName::Defined(parsed),
                        kind: param.value().kind(),
                        presence: param.value().presence(),
                    })
                })
                .collect::<Result<Vec<ParamForm>, DefinedError>>()?;
            let mut compiling = Compiling {
                key,
                params: &params,
                locale: &locale,
                main,
                expressions: Vec::new(),
            };
            let body = match body {
                Body::Pattern(parts) => BodyForm::Pattern(compiling.pattern(parts)?),
                Body::Select {
                    selectors,
                    variants,
                } => compiling.select(selectors, variants)?,
            };
            let expressions = compiling.expressions;
            messages.push(MessageForm {
                id: key.to_owned(),
                params,
                expressions,
                body,
            });
        }
        messages.sort_by(|a, b| a.id.cmp(&b.id));
        self.locales.push(DefinedLocale {
            locale,
            direction: main.map_or(Direction::Unknown, MainLocale::direction),
            messages,
        });
        Ok(())
    }

    /// The module: its digest the SHA-256 of each locale's tag, direction and messages, in the
    /// order given.
    #[must_use]
    pub fn finish(self) -> DefinedForm {
        let mut writer = Writer::default();
        writer.count(self.locales.len());
        for locale in &self.locales {
            writer.text(locale.locale.as_str());
            write_direction(&mut writer, locale.direction);
            writer.count(locale.messages.len());
            for message in &locale.messages {
                write_message(&mut writer, message);
            }
        }
        DefinedForm {
            id: self.id,
            digest: Sha256::digest(writer.finish()).into(),
            policy: self.policy,
            locales: self.locales,
        }
    }
}
