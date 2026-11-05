//! PaSO View's display rules as a defined module (section 4.14 of the design): the conversion the
//! wallet runs when a type's metadata loads, and the identity and keys phase 1's texts name.
//!
//! Each display array is one message of the module, under the key of what it labels: a claim's
//! `claim_<k>`, a UI label's name. The module supports each tag of the End-User's priority list
//! View §4 can select ([`crate::locale::selectable`]); in each, an array's message is the text of
//! the entries View §4 tries for that tag ([`crate::locale::chain`]): one entry's, or for a
//! template that an absent claim discards, a `.match` over each such entry's argument `e<j>`
//! (`live` or `dead`, by its position) whose catch-all is the last entry tried. A plain label is
//! literal text, a `mini_markdown` label its emphasis, strong and underline spans as MF2 markup, a
//! template label its spans with each `{n}` naming a claim as the argument `c<n>` of claim n's
//! value kind, absent when the claim is. Each tag copies the main module's options of the formats
//! its arguments call, and its direction when it states one, from the main module's resource
//! RFC 4647 Lookup finds for the tag; a tag no main resource serves where an argument calls a
//! format has no source, and a screen showing the module in it refuses it. Its language policy is
//! `Understood`: View §4 excludes a credential when no tag matches every array.

use std::borrow::Cow;

use sha2::{Digest, Sha256};
use siros_explain::{
    ArgKind, DefinedKey, DefinedModule, Domain, Entry, Explain, Keyed, ParamKind, Presence, checked,
};
use siros_i18n::{LanguagePolicy, LocaleTag};
use siros_openid4vp::json::Node;

use crate::locale::{ArrayKey, chain, lookup, selectable};
use crate::markdown::{Span, Style, spans};
use crate::metadata::{ClaimMeta, DisplayArray, LabelForm, Localized, ValueType};
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

/// The key of a display array's message: `claim_<index>` for a claim's, the UI label's name for
/// a UI label's.
pub(crate) fn key(array: ArrayKey) -> DefinedKey {
    match array {
        ArrayKey::Claim(claim) => DefinedKey::numbered(CLAIM, &[claim.0]),
        ArrayKey::Ui(ui) => DefinedKey::numbered(ui.stem(), &[]),
    }
}

/// The name of the argument a template's `{n}` gives claim n's value under.
pub(crate) fn argument(claim: usize) -> Cow<'static, str> {
    Cow::Owned(format!("c{claim}"))
}

/// The name of the argument that tells whether the template entry at `position` of an array is
/// discarded.
pub(crate) fn liveness(position: usize) -> Cow<'static, str> {
    Cow::Owned(format!("e{position}"))
}

/// The value of a liveness argument for an entry no absent claim discards.
pub(crate) const LIVE: &str = "live";
/// The value of a liveness argument for an entry an absent claim discards.
pub(crate) const DEAD: &str = "dead";

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
    /// Each array's key, with its template entries' liveness and referenced values as arguments,
    /// and their kinds.
    pub declaration: Keyed<DefinedKey, Keyed<Cow<'static, str>, ParamKind>>,
    /// For each tag it supports, once, its resource.
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
    /// A display array holds no entry for a language the converted module supports.
    #[error("a display array holds no entry for {0}")]
    NoEntry(#[explain(name = "locale")] LocaleTag),
    /// A display array mixes the wallet's own labels with the metadata's.
    #[error("a display array mixes the wallet's own labels with the metadata's")]
    MixedOwn,
}

/// One language of the main module: its tag, its direction when it states one, and its format
/// sections.
struct Language<'s> {
    tag: LocaleTag,
    dir: Option<&'s str>,
    sections: Vec<(&'s str, &'s str)>,
}

impl<'s> Language<'s> {
    /// A main module's resource: `@locale`, `@dir` before `---`, then its `[formats.<name>]`
    /// sections, each to the next section. siros-paso builds without siros-i18n's loader, whose
    /// parser checks the resource when the app loads the main module.
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
        let dir = meta("@dir ");
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

/// An array to convert: what it labels, its entries, and its message's parameters.
struct Converting<'a, 'm> {
    array: ArrayKey,
    entries: &'a DisplayArray<'m>,
    params: Keyed<Cow<'static, str>, ParamKind>,
}

/// Converts a type's display rules into its defined module for the End-User's priority list,
/// over the main module's resources, one per language, whose format options it copies.
///
/// # Errors
///
/// [`ConvertError`]: the type is no PaSO type, its metadata refuses, a main resource names no
/// locale or lacks a format the module calls, or a template holds U+FDD0.
pub fn convert(
    kind: &str,
    given: &Node<'_>,
    main: &[&str],
    priority: &[LocaleTag],
) -> Result<Converted, ConvertError> {
    let family = Family::of(kind).ok_or_else(|| ConvertError::NotPaso(kind.to_owned()))?;
    let (metadata, _) = rulebook_metadata(kind, family, given)?;
    let arrays = arrays(&metadata);
    let main = main
        .iter()
        .enumerate()
        .map(|(index, source)| Language::read(index, source))
        .collect::<Result<Vec<_>, _>>()?;
    let mut wallet: Vec<LocaleTag> = Vec::new();
    for language in &main {
        if wallet.contains(&language.tag) {
            return Err(ConvertError::Locale(language.tag.clone()));
        }
        wallet.push(language.tag.clone());
    }
    let mut messages: Vec<Converting<'_, '_>> = Vec::new();
    for (array, entries) in &arrays {
        if entries
            .entries()
            .iter()
            .all(|entry| matches!(entry.label, LabelForm::Own(_)))
        {
            continue;
        }
        let mut params = Vec::new();
        for (position, entry) in entries.entries().iter().enumerate() {
            if let LabelForm::Template(text) = entry.label {
                params.push(Entry::new(
                    liveness(position),
                    ParamKind::new(ArgKind::Name, Presence::Required),
                ));
                params.extend(template(text, &metadata.claims)?.1.into_entries());
            }
        }
        messages.push(Converting {
            array: *array,
            entries,
            params: Keyed::first_of(params),
        });
    }
    let mut formats: Vec<&'static str> = Vec::new();
    for message in &messages {
        for param in message.params.entries() {
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
    for tag in selectable(&arrays, priority) {
        let language = lookup(&tag, &wallet)
            .and_then(|found| main.iter().find(|language| language.tag == *found));
        if language.is_none() && !formats.is_empty() {
            continue;
        }
        let mut text = format!("@locale {}\n", tag.as_str());
        if let Some(dir) = language.and_then(|language| language.dir) {
            text.push_str(&format!("@dir {dir}\n"));
        }
        text.push_str("---\n");
        for message in &messages {
            let pattern = message_in(message, &tag, &metadata.claims)?;
            text.push_str(&format!("{} = {pattern}\n", key(message.array).as_str()));
        }
        for format in &formats {
            let (_, options) = language
                .iter()
                .flat_map(|language| language.sections.iter())
                .find(|(name, _)| name == format)
                .ok_or_else(|| ConvertError::Format {
                    format,
                    locale: tag.clone(),
                })?;
            text.push_str(&format!("\n[formats.{format}]\n{options}\n"));
        }
        sources.push(Entry::new(tag, text));
    }
    let declaration = messages
        .into_iter()
        .map(|message| Entry::new(key(message.array), message.params));
    Ok(Converted {
        module: module_of(given),
        declaration: Keyed::first_of(declaration),
        sources: Keyed::first_of(sources),
        policy: LanguagePolicy::Understood,
    })
}

/// An array's message in a language: the pattern of the one entry the language takes, or a
/// `.match` over the liveness of each template entry it takes before its last.
fn message_in(
    message: &Converting<'_, '_>,
    language: &LocaleTag,
    claims: &[ClaimMeta<'_>],
) -> Result<String, ConvertError> {
    let taken = chain(message.entries, language);
    let patterns = taken
        .iter()
        .map(|(_, entry)| pattern(entry, claims))
        .collect::<Result<Vec<_>, _>>()?;
    let Some((last, before)) = patterns.split_last() else {
        return Err(ConvertError::NoEntry(language.clone()));
    };
    if before.is_empty() {
        return Ok(format!("{{{{{last}}}}}"));
    }
    let mut out = String::new();
    for (position, _) in taken.iter().take(before.len()) {
        out.push_str(&format!(".input {{${} :string}} ", liveness(*position)));
    }
    out.push_str(".match");
    for (position, _) in taken.iter().take(before.len()) {
        out.push_str(&format!(" ${}", liveness(*position)));
    }
    for (k, pattern) in before.iter().enumerate() {
        out.push(' ');
        for column in 0..before.len() {
            out.push_str(if column == k { LIVE } else { "*" });
            out.push(' ');
        }
        out.push_str(&format!("{{{{{pattern}}}}}"));
    }
    out.push(' ');
    for _ in 0..before.len() {
        out.push_str("* ");
    }
    out.push_str(&format!("{{{{{last}}}}}"));
    Ok(out)
}

/// An entry's label as an MF2 pattern's text.
fn pattern(entry: &Localized<'_>, claims: &[ClaimMeta<'_>]) -> Result<String, ConvertError> {
    Ok(match entry.label {
        LabelForm::Plain(text) => literal(text.as_str()),
        LabelForm::Markdown(text) => markup(&spans(text.as_str())),
        LabelForm::Template(text) => template(text, claims)?.0,
        LabelForm::Own(_) => return Err(ConvertError::MixedOwn),
    })
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
            ParamKind::new(argument_kind(value_type), Presence::Optional),
        )
    });
    Ok((out, Keyed::first_of(params)))
}
