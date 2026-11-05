//! A module loaded whole: its declaration, its sources in every locale it supports, parsed and
//! checked, and compiled into its render form.

use sha2::{Digest, Sha256};
use std::borrow::Cow;

use siros_explain::{DefinedKey, Entry, Keyed, Message, ModuleId, ParamKind};

use crate::compile::{self, Site};
use crate::error::{ModuleError, OptionRefusal};
use crate::form::{
    BareCalls, BareKind, CompiledCall, CompiledModule, LanguagePolicy, LocaleForm, ParamForm,
};
use crate::format::{
    Call, Compilers, FormatCompiler, FormatId, LanguageFormats, Operand, ParsedFormats, Uses,
};
use crate::locale::LocaleTag;
use crate::mf2::{parse, valid};
use crate::resource::{self, Resource};

/// A module's declaration: its keys, and each key's arguments with their kinds. A crate module's
/// is its types' [`siros_explain::Messages`]; a defined module's is what its converter declares.
/// Only [`Declaration::new`] and [`Declaration::defined`] make one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declaration {
    messages: Vec<Declared>,
}

/// A declared message: its identifier, its English template when a type declared it, and its
/// parameters in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Declared {
    pub(crate) id: String,
    text: Option<&'static str>,
    pub(crate) params: Vec<ParamForm>,
}

impl Declaration {
    /// The declaration of the messages, each identifier once: a message two transparent variants
    /// reach is counted once. A message's argument names are distinct by
    /// [`siros_explain::Names`].
    ///
    /// # Errors
    ///
    /// [`ModuleError::Declaration`] for two different messages under one identifier.
    pub fn new(messages: Vec<Message>) -> Result<Self, ModuleError> {
        Self::of(messages.iter().map(|message| Declared {
            id: message.id().as_str().to_owned(),
            text: message.text(),
            params: ParamForm::of_message(message),
        }))
    }

    /// The declaration a converter writes for a defined module: each key with its parameters,
    /// each under its name, in order.
    ///
    /// # Errors
    ///
    /// [`ModuleError::ParameterName`] for a parameter name that is no tokens, the grammar of an
    /// [`ArgName`](siros_explain::ArgName) and of a [`DefinedKey`].
    pub fn defined(
        messages: Keyed<DefinedKey, Keyed<Cow<'static, str>, ParamKind>>,
    ) -> Result<Self, ModuleError> {
        let mut declared = Vec::with_capacity(messages.entries().len());
        for entry in messages.entries() {
            let mut params = Vec::with_capacity(entry.value().entries().len());
            for param in entry.value().entries() {
                let name = param.key().clone().into_owned();
                if DefinedKey::parse(name.clone()).is_none() {
                    return Err(ModuleError::ParameterName {
                        key: entry.key().as_str().to_owned(),
                        name,
                    });
                }
                params.push(ParamForm {
                    name,
                    kind: param.value().kind(),
                    presence: param.value().presence(),
                });
            }
            declared.push(Declared {
                id: entry.key().as_str().to_owned(),
                text: None,
                params,
            });
        }
        Self::of(declared.into_iter())
    }

    fn of(messages: impl Iterator<Item = Declared>) -> Result<Self, ModuleError> {
        let mut held: Vec<Declared> = Vec::new();
        for message in messages {
            match held.iter().find(|earlier| earlier.id == message.id) {
                Some(earlier) if *earlier == message => {}
                Some(_) => return Err(ModuleError::Declaration(message.id)),
                None => held.push(message),
            }
        }
        held.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(Self { messages: held })
    }

    /// The declared identifiers, sorted.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.messages.iter().map(|message| message.id.as_str())
    }
}

/// A module, parsed and checked when it loaded: for each locale it supports, every key's message,
/// compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    form: CompiledModule,
}

/// A format module a module uses: for its messages' calls, and for the main module's bare values
/// of the kinds whose implicit function it provides.
struct Used {
    compiler: &'static dyn FormatCompiler,
    bare: Vec<Implicit>,
}

/// A bare value's kind, and the function its format calls.
#[derive(Clone, Copy)]
struct Implicit {
    kind: BareKind,
    function: &'static str,
}

/// One format module's options in one locale, as its compiler parsed them, and the bare kinds it
/// formats.
struct Parsed<'u> {
    id: FormatId,
    formats: Box<dyn ParsedFormats>,
    bare: &'u [Implicit],
}

/// One locale's formats, as their compilers parsed them.
struct LocaleFormats<'u> {
    parsed: Vec<Parsed<'u>>,
}

impl LocaleFormats<'_> {
    fn get(&self, id: FormatId) -> Option<&dyn ParsedFormats> {
        self.parsed
            .iter()
            .find(|parsed| parsed.id == id)
            .map(|parsed| &*parsed.formats)
    }
}

/// The format modules a module uses: its messages', then those of the bare kinds `bare`.
fn used(
    messages: impl Iterator<Item = &'static dyn FormatCompiler>,
    bare: &[BareKind],
    compilers: &Compilers,
) -> Vec<Used> {
    let mut used: Vec<Used> = Vec::new();
    for compiler in messages {
        if used.iter().all(|u| u.compiler.id() != compiler.id()) {
            used.push(Used {
                compiler,
                bare: Vec::new(),
            });
        }
    }
    for &kind in bare {
        let Some((compiler, function)) = compilers.provider(compile::implicit(kind.arg_kind()))
        else {
            continue;
        };
        let implicit = Implicit { kind, function };
        match used.iter_mut().find(|u| u.compiler.id() == compiler.id()) {
            Some(u) => u.bare.push(implicit),
            None => used.push(Used {
                compiler,
                bare: vec![implicit],
            }),
        }
    }
    used
}

impl Module {
    /// Parses every message of every source now, each source a resource of one locale, and
    /// compiles each placeholder with the registered load halves. The main module also compiles
    /// the format of a bare value of each kind a registered module formats. `policy`: a defined
    /// module's is its converted module's; the app answers for a module no specification
    /// governs.
    ///
    /// # Errors
    ///
    /// The [`ModuleError`] of the first rule the module breaks, the rules checked in this order:
    ///
    /// 1. a declared message outside the module's domain;
    /// 2. source by source: the resource format, then a locale given twice;
    /// 3. locale by locale, in the sources' order: a key given twice or undeclared, in the
    ///    source's order; then key by key, in the declaration's order: the key missing, then its
    ///    message not parsing, breaking MF2's data model, naming an undeclared argument, calling a
    ///    function no registered module provides, giving a `u:` option the loader refuses, or
    ///    holding markup outside the styles or unbalanced, in the message's order;
    /// 4. locale by locale: options of a format no message calls, an option given twice, an
    ///    option its format does not take, then each used format's options missing, refused by
    ///    the format, or listed twice by it; then each placeholder's call refused by its function,
    ///    message by message; then the main module's formats of bare values.
    pub fn load(
        id: ModuleId,
        declared: &Declaration,
        sources: &[&str],
        policy: LanguagePolicy,
        compilers: &Compilers,
    ) -> Result<Self, ModuleError> {
        let prefix = match id {
            ModuleId::Crate(domain) => format!("{}.", domain.as_str()),
            ModuleId::Main | ModuleId::Defined(_) => String::new(),
        };
        let mut keyed: Vec<Entry<&str, &Declared>> = Vec::with_capacity(declared.messages.len());
        for message in &declared.messages {
            let key = message.id.strip_prefix(prefix.as_str());
            let key = key.ok_or_else(|| ModuleError::Outside(message.id.clone()))?;
            keyed.push(Entry::new(key, message));
        }
        let mut resources: Vec<Resource> = Vec::with_capacity(sources.len());
        let mut digest = Sha256::new();
        for (index, text) in sources.iter().enumerate() {
            let resource = resource::parse(index, text)?;
            if resources
                .iter()
                .any(|earlier| earlier.locale == resource.locale)
            {
                return Err(ModuleError::Locale(resource.locale.to_string()));
            }
            digest.update((text.len() as u64).to_be_bytes());
            digest.update(text.as_bytes());
            resources.push(resource);
        }
        let mut resolved = Vec::with_capacity(resources.len());
        for resource in &resources {
            resolved.push(resolve(resource, &keyed, compilers)?);
        }
        let bare = if id == ModuleId::Main {
            BareKind::ALL.as_slice()
        } else {
            &[]
        };
        let messages = resolved
            .iter()
            .flatten()
            .flat_map(compile::Resolved::compilers);
        let used = used(messages, bare, compilers);
        let mut locales = Vec::with_capacity(resources.len());
        for (resource, messages) in resources.iter().zip(resolved) {
            let formats = parse_formats(resource, &used)?;
            let mut forms = Vec::with_capacity(messages.len());
            for message in messages {
                forms.push(message.compile(&|id| formats.get(id))?);
            }
            forms.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
            let mut calls = BareCalls::default();
            for parsed in &formats.parsed {
                for implicit in parsed.bare {
                    calls.set(implicit.kind, bare_call(resource, parsed, *implicit)?);
                }
            }
            locales.push(LocaleForm {
                locale: resource.locale.clone(),
                direction: resource.direction,
                messages: forms,
                bare: calls,
            });
        }
        Ok(Self {
            form: CompiledModule {
                id,
                digest: digest.finalize().into(),
                policy,
                locales,
            },
        })
    }

    /// The module's identity.
    #[must_use]
    pub const fn id(&self) -> ModuleId {
        self.form.id
    }

    /// The SHA-256 of its loaded sources, format options included, each source its length as a
    /// big-endian `u64` and its bytes, in the order given.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.form.digest
    }

    /// The locales it supports, in its sources' order.
    pub fn locales(&self) -> impl Iterator<Item = &LocaleTag> {
        self.form.locales.iter().map(|form| &form.locale)
    }

    /// Its render form, which a package carries.
    pub(crate) const fn form(&self) -> &CompiledModule {
        &self.form
    }
}

/// One locale's messages, each parsed, checked and resolved.
fn resolve<'a>(
    resource: &'a Resource,
    keyed: &[Entry<&'a str, &'a Declared>],
    compilers: &Compilers,
) -> Result<Vec<compile::Resolved<'a>>, ModuleError> {
    let locale = resource.locale.as_str();
    let at = |key: &str| (key.to_owned(), locale.to_owned());
    for (index, entry) in resource.messages.iter().enumerate() {
        if resource
            .messages
            .iter()
            .take(index)
            .any(|earlier| earlier.key == entry.key)
        {
            let (key, locale) = at(&entry.key);
            return Err(ModuleError::Repeated { key, locale });
        }
        if keyed.iter().all(|declared| *declared.key() != entry.key) {
            let (key, locale) = at(&entry.key);
            return Err(ModuleError::Undeclared { key, locale });
        }
    }
    let mut resolved = Vec::with_capacity(keyed.len());
    for declared in keyed {
        let key = *declared.key();
        let Some(entry) = resource.messages.iter().find(|entry| entry.key == key) else {
            let (key, locale) = at(key);
            return Err(ModuleError::Missing { key, locale });
        };
        let message = parse::parse(&entry.value).map_err(|error| {
            let (key, locale) = at(key);
            ModuleError::Syntax {
                key,
                locale,
                at: error.0,
            }
        })?;
        valid::check(&message).map_err(|rule| {
            let (key, locale) = at(key);
            ModuleError::Invalid { key, locale, rule }
        })?;
        let site = Site {
            key,
            locale,
            message: declared.value(),
        };
        resolved.push(compile::resolve(site, &message, compilers)?);
    }
    Ok(resolved)
}

/// A locale's options of each format the module uses, parsed by the format's compiler.
fn parse_formats<'u>(
    resource: &Resource,
    used: &'u [Used],
) -> Result<LocaleFormats<'u>, ModuleError> {
    let locale = resource.locale.to_string();
    for section in &resource.formats {
        let compiler = used
            .iter()
            .map(|u| u.compiler)
            .find(|compiler| compiler.id().as_str() == section.format);
        let Some(compiler) = compiler.filter(|compiler| !compiler.options().is_empty()) else {
            return Err(ModuleError::Format {
                format: section.format.clone(),
                locale,
            });
        };
        for (index, option) in section.options.iter().enumerate() {
            if section
                .options
                .iter()
                .take(index)
                .any(|earlier| earlier.key == option.key)
            {
                return Err(ModuleError::Repeated {
                    key: format!("formats.{}.{}", section.format, option.key),
                    locale,
                });
            }
            if !compiler.options().contains(&option.key.as_str()) {
                return Err(ModuleError::UnknownOption {
                    format: section.format.clone(),
                    option: option.key.clone(),
                    locale,
                });
            }
        }
    }
    let mut parsed = Vec::with_capacity(used.len());
    for Used { compiler, bare } in used {
        let section = resource
            .formats
            .iter()
            .find(|section| section.format == compiler.id().as_str());
        let mut options = Vec::with_capacity(compiler.options().len());
        for &option in compiler.options() {
            let text = section
                .and_then(|section| section.options.iter().find(|entry| entry.key == option));
            let Some(text) = text else {
                return Err(ModuleError::Option {
                    format: compiler.id().as_str(),
                    option,
                    locale,
                });
            };
            options.push(Entry::new(option, text.value.as_str()));
        }
        let options = Keyed::new(options).map_err(|repeated| ModuleError::Listed {
            format: compiler.id().as_str(),
            option: repeated.0,
        })?;
        let language = LanguageFormats::new(&resource.locale, resource.direction, &options);
        let formats = compiler
            .parse(&language)
            .map_err(|refused| match refused.cause() {
                OptionRefusal::Text(text) => ModuleError::OptionText {
                    format: compiler.id().as_str(),
                    option: refused.option(),
                    locale: locale.clone(),
                    text: text.clone(),
                },
                OptionRefusal::Undeclared => ModuleError::UndeclaredOption {
                    format: compiler.id().as_str(),
                    option: refused.option(),
                },
            })?;
        parsed.push(Parsed {
            id: compiler.id(),
            formats,
            bare,
        });
    }
    Ok(LocaleFormats { parsed })
}

/// The main module's format of a bare value of one kind, in one locale.
fn bare_call(
    resource: &Resource,
    parsed: &Parsed<'_>,
    implicit: Implicit,
) -> Result<CompiledCall, ModuleError> {
    let options = Keyed::empty();
    let call = Call::new(
        implicit.function,
        Operand::Argument(implicit.kind.arg_kind()),
        &options,
        Uses::new(true, false),
    );
    let bytes = parsed
        .formats
        .compile(&call)
        .map_err(|refusal| ModuleError::Bare {
            kind: implicit.kind,
            locale: resource.locale.to_string(),
            function: implicit.function,
            refusal,
        })?;
    Ok(CompiledCall {
        format: parsed.id.as_str().to_owned(),
        bytes,
    })
}
