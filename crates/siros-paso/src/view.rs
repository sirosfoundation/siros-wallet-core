//! PaSO View's display rules as a defined module (section 4.14 of the design): the conversion the
//! wallet runs when a type's metadata loads, and the identity and keys phase 1's texts name.
//!
//! Each label of the metadata's display arrays, at its position in its array, is one message of
//! the module, the same in every language it supports: View §4 chooses the entry, and the
//! language chooses the format options of a template's values. A plain label is literal text, a
//! `mini_markdown` label its emphasis, strong and underline spans as MF2 markup, a template
//! label its spans with each `{n}` naming a claim as an argument of claim n's value kind. The
//! module supports each language of the main module that every display array serves (View §4,
//! RFC 4647 basic filtering, or a default entry), and copies the main module's options of the
//! formats its arguments call in that language. Its language policy is `Understood`: View §4
//! excludes a credential when no language the End-User understands serves every array.

use std::borrow::Cow;

use sha2::{Digest, Sha256};
use siros_explain::{
    ArgKind, DefinedKey, DefinedModule, Domain, Entry, Explain, Keyed, ParamKind, Presence, checked,
};
use siros_i18n::{LanguagePolicy, LocaleTag};
use siros_openid4vp::json::Node;
use siros_openid4vp::text::lookup;

use crate::locale::ArrayKey;
use crate::markdown::{Span, Style, spans};
use crate::metadata::{ClaimMeta, EntryLocale, LabelForm, Localized, ValueType};
use crate::outcome::Outcome;
use crate::render::{arrays, rulebook_metadata};
use crate::rulebook::Family;
use crate::template::{Placeholder, placeholders};
use crate::value::{FormattedKind, ValueKind};

/// The plug-in whose conversions name PaSO's defined modules.
pub const PLUGIN: Domain = checked!(Domain, "paso");

/// The character a template's claim placeholders stand as while its `mini_markdown` is read.
const SLOT: char = '\u{FDD0}';

/// The defined module a type's metadata converts to: PaSO's, under the SHA-256 of the
/// metadata's compact JSON.
#[must_use]
pub fn module_of(given: &Node<'_>) -> DefinedModule {
    let digest = Sha256::digest(given.python_compact().to_string().as_bytes());
    DefinedModule::new(PLUGIN, digest.into())
}

/// The stem of a claim's labels' keys.
const CLAIM: Domain = checked!(Domain, "claim");

/// The key of the label at `position` of a display array: `claim_<index>_<position>` for a
/// claim's, `<ui label>_<position>` for a UI label's.
pub(crate) fn key(array: ArrayKey, position: usize) -> DefinedKey {
    match array {
        ArrayKey::Claim(claim) => DefinedKey::numbered(CLAIM, &[claim.0, position]),
        ArrayKey::Ui(ui) => DefinedKey::numbered(ui.stem(), &[position]),
    }
}

/// The name of the argument a template's `{n}` gives claim n's value under.
pub(crate) fn argument(claim: usize) -> Cow<'static, str> {
    Cow::Owned(format!("c{claim}"))
}

/// The kind of value a template's `{n}` gives, by claim n's value type: a typed value for a
/// date, a time, a date and time, a currency and an amount; a message for a boolean and a
/// frequency; the text as written otherwise.
pub(crate) const fn argument_kind(value_type: ValueType) -> ArgKind {
    match value_type {
        ValueType::Kind(ValueKind::Formatted(kind)) => match kind {
            FormattedKind::Boolean | FormattedKind::Frequency => ArgKind::Message,
            FormattedKind::Date => ArgKind::Date,
            FormattedKind::Time => ArgKind::Time,
            FormattedKind::DateTime => ArgKind::DateTime,
            FormattedKind::Currency => ArgKind::Currency,
            FormattedKind::CurrencyAmount => ArgKind::Amount,
            FormattedKind::Text | FormattedKind::MiniMarkdown | FormattedKind::Url => ArgKind::Raw,
        },
        ValueType::Plain
        | ValueType::Kind(ValueKind::Image)
        | ValueType::LabelOnly
        | ValueType::Template(_) => ArgKind::Raw,
    }
}

/// A type's display rules as a defined module's declaration and sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Converted {
    /// The module's identity.
    pub module: DefinedModule,
    /// Each label's key, with a template's arguments and their kinds.
    pub declaration: Keyed<DefinedKey, Keyed<Cow<'static, str>, ParamKind>>,
    /// For each language it supports, once, its resource.
    pub sources: Keyed<LocaleTag, String>,
    /// View §4's: `Understood`.
    pub policy: LanguagePolicy,
}

/// Why a type's metadata does not convert.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "paso.convert")]
pub enum ConvertError {
    /// The type is no PaSO type.
    #[error("{0} is no urn:paso:sca: type")]
    NotPaso(#[explain(name = "type")] String),
    /// The metadata breaks Proof Metadata §3, or a value type is unsupported.
    #[error(transparent)]
    Metadata(#[from] Outcome),
    /// A main module's resource names no locale.
    #[error("the main module's resource {0} names no locale")]
    Main(#[explain(name = "source")] usize),
    /// The main module lacks a format's options in a language the module supports.
    #[error("the main module defines no {format} options for {locale}")]
    Format {
        /// The format.
        format: &'static str,
        /// The language.
        locale: LocaleTag,
    },
    /// A template holds the character the conversion reads its placeholders as.
    #[error("a template holds U+FDD0")]
    Reserved,
    /// Two main module resources name one locale.
    #[error("two main module resources name {0}")]
    Locale(#[explain(name = "locale")] LocaleTag),
}

/// One language of the main module: its tag, its direction, and its format sections.
struct Language<'s> {
    tag: LocaleTag,
    dir: &'s str,
    sections: Vec<(&'s str, &'s str)>,
}

impl<'s> Language<'s> {
    /// A main module's resource: `@locale`, `@dir` before `---`, then its `[formats.<name>]`
    /// sections, each to the next section.
    fn read(index: usize, source: &'s str) -> Result<Self, ConvertError> {
        let (head, body) = source
            .split_once("\n---\n")
            .ok_or(ConvertError::Main(index))?;
        let meta = |name: &str| {
            head.lines()
                .find_map(|line| line.strip_prefix(name).map(str::trim))
        };
        let tag = meta("@locale ")
            .and_then(|tag| LocaleTag::parse(tag).ok())
            .ok_or(ConvertError::Main(index))?;
        let dir = meta("@dir ").unwrap_or("ltr");
        let mut sections = Vec::new();
        for part in body.split("\n[formats.").skip(1) {
            if let Some((name, options)) = part.split_once("]\n") {
                let options = options.split("\n[").next().unwrap_or_default();
                sections.push((name, options));
            }
        }
        Ok(Self { tag, dir, sections })
    }
}

/// Converts a type's display rules into its defined module, over the main module's resources,
/// one per language, whose format options it copies.
///
/// # Errors
///
/// [`ConvertError`]: the type is no PaSO type, its metadata refuses, a main resource names no
/// locale or lacks a format the module calls, or a template holds U+FDD0.
pub fn convert(kind: &str, given: &Node<'_>, main: &[&str]) -> Result<Converted, ConvertError> {
    let family = Family::of(kind).ok_or_else(|| ConvertError::NotPaso(kind.to_owned()))?;
    let (metadata, _) = rulebook_metadata(kind, family, given)?;
    let arrays = arrays(&metadata);
    let mut messages: Vec<(DefinedKey, String, Keyed<Cow<'static, str>, ParamKind>)> = Vec::new();
    for (array, entries) in &arrays {
        for (position, entry) in entries.entries().iter().enumerate() {
            let (pattern, params) = match entry.label {
                LabelForm::Plain(text) => (literal(text.as_str()), Keyed::empty()),
                LabelForm::Markdown(text) => (markup(&spans(text.as_str())), Keyed::empty()),
                LabelForm::Template(text) => template(text, &metadata.claims)?,
                LabelForm::Own(_) => continue,
            };
            messages.push((key(*array, position), pattern, params));
        }
    }
    let mut formats: Vec<&'static str> = Vec::new();
    for (_, _, params) in &messages {
        for param in params.entries() {
            let format = match param.value().kind() {
                ArgKind::Date | ArgKind::Time | ArgKind::DateTime => "date",
                ArgKind::Amount | ArgKind::Currency => "currency",
                _ => continue,
            };
            if !formats.contains(&format) {
                formats.push(format);
            }
        }
    }
    let mut sources = Vec::new();
    for (index, source) in main.iter().enumerate() {
        let language = Language::read(index, source)?;
        if !arrays
            .iter()
            .all(|(_, entries)| serves(&language.tag, entries.entries()))
        {
            continue;
        }
        let mut text = format!(
            "@locale {}\n@dir {}\n---\n",
            language.tag.as_str(),
            language.dir
        );
        for (key, pattern, _) in &messages {
            text.push_str(&format!("{} = {{{{{pattern}}}}}\n", key.as_str()));
        }
        for format in &formats {
            let (_, options) = language
                .sections
                .iter()
                .find(|(name, _)| name == format)
                .ok_or_else(|| ConvertError::Format {
                    format,
                    locale: language.tag.clone(),
                })?;
            text.push_str(&format!("\n[formats.{format}]\n{options}\n"));
        }
        sources.push(Entry::new(language.tag, text));
    }
    let declaration = messages
        .into_iter()
        .map(|(key, _, params)| Entry::new(key, params));
    Ok(Converted {
        module: module_of(given),
        declaration: Keyed::first_of(declaration),
        sources: Keyed::new(sources).map_err(|repeated| ConvertError::Locale(repeated.0))?,
        policy: LanguagePolicy::Understood,
    })
}

/// Whether View §4 serves a language in an array: an entry the language matches by basic
/// filtering, or a default entry.
fn serves(tag: &LocaleTag, entries: &[Localized<'_>]) -> bool {
    let tags: Vec<&str> = entries
        .iter()
        .filter_map(|entry| match entry.locale {
            EntryLocale::Tagged(tag) => Some(tag),
            EntryLocale::Default => None,
        })
        .collect();
    lookup(tag, &tags).is_some()
        || entries
            .iter()
            .any(|entry| entry.locale == EntryLocale::Default)
}

/// Text as an MF2 quoted pattern's literal: MF2's escapes, and the resource's for a character a
/// resource line does not hold.
fn literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' | '{' | '}' => {
                out.push('\\');
                out.push(c);
            }
            ' ' | '\t' | '\u{21}'..='\u{7E}' | '\u{A0}'..='\u{2027}' | '\u{202A}'..='\u{FFFF}' => {
                out.push(c);
            }
            c if u32::from(c) > 0xFFFF => out.push(c),
            c => {
                out.push_str(&format!("\\u{:04X}", u32::from(c)));
            }
        }
    }
    out
}

/// The styles of a span, outermost first, as MF2 markup names them.
fn styles(style: Style) -> impl DoubleEndedIterator<Item = &'static str> {
    [
        (Style::STRONG, "strong"),
        (Style::EM, "emphasis"),
        (Style::UNDERLINE, "underline"),
    ]
    .into_iter()
    .filter(move |(bit, _)| style.has(*bit))
    .map(|(_, name)| name)
}

/// Styled spans as MF2: each span's text inside markup that opens its styles and closes them.
fn markup(spans: &[Span]) -> String {
    let mut out = String::new();
    for span in spans {
        for name in styles(span.style) {
            out.push_str(&format!("{{#{name}}}"));
        }
        out.push_str(&literal(&span.text));
        for name in styles(span.style).rev() {
            out.push_str(&format!("{{/{name}}}"));
        }
    }
    out
}

/// A `template:mini_markdown` label: its spans with each placeholder naming a claim as that
/// claim's argument, other placeholders literal; and the arguments with their kinds.
fn template(
    text: &str,
    claims: &[ClaimMeta<'_>],
) -> Result<(String, Keyed<Cow<'static, str>, ParamKind>), ConvertError> {
    if text.contains(SLOT) {
        return Err(ConvertError::Reserved);
    }
    let named: Vec<(Placeholder, usize)> = placeholders(text)
        .into_iter()
        .filter_map(|placeholder| {
            let index = placeholder.index.filter(|index| *index < claims.len())?;
            Some((placeholder, index))
        })
        .collect();
    let mut marked = String::with_capacity(text.len());
    let mut copied = 0;
    for (placeholder, _) in &named {
        marked.push_str(text.get(copied..placeholder.span.start).unwrap_or_default());
        marked.push(SLOT);
        copied = placeholder.span.end;
    }
    marked.push_str(text.get(copied..).unwrap_or_default());
    let mut indices = named.iter().map(|(_, index)| *index);
    let mut out = String::new();
    for span in spans(&marked) {
        for name in styles(span.style) {
            out.push_str(&format!("{{#{name}}}"));
        }
        for (k, part) in span.text.split(SLOT).enumerate() {
            if k > 0
                && let Some(index) = indices.next()
            {
                out.push_str(&format!("{{${}}}", argument(index)));
            }
            out.push_str(&literal(part));
        }
        for name in styles(span.style).rev() {
            out.push_str(&format!("{{/{name}}}"));
        }
    }
    let params = named.iter().map(|(_, index)| {
        let value_type = claims
            .get(*index)
            .and_then(|claim| claim.display.as_ref())
            .map_or(ValueType::Plain, |display| display.value);
        Entry::new(
            argument(*index),
            ParamKind::new(argument_kind(value_type), Presence::Required),
        )
    });
    Ok((out, Keyed::first_of(params)))
}
