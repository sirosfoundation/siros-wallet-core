//! PaSO View's display rules as a defined module (section 4.14 of the design): the conversion the
//! wallet runs when a type's metadata loads, and the matcher when ad-hoc metadata arrives with a
//! request, and the identity and keys phase 1's texts name.
//!
//! Each display array is one message of the module, under the key of what it labels: a claim's
//! `claim_<k>`, a UI label's name. The module supports each tag of the End-User's priority list
//! View §4 can select ([`crate::locale::selectable`]); in each, an array's message is the text of
//! the entries View §4 tries for that tag ([`crate::locale::chain`]): one entry's, or for a
//! template that an absent claim discards, a selection over each such entry's argument `e<j>`
//! (`live` or `dead`, by its position) whose fallback is the last entry tried. A plain label is
//! literal text, a `mini_markdown` label its emphasis, strong and underline spans as styles, a
//! template label its spans with each `{n}` naming a claim as the argument `c<n>` of claim n's
//! value kind, absent when the claim is. The conversion writes the module in its render form with
//! no loader ([`DefinedForm`]): each tag's typed arguments format as the main module's entry RFC
//! 4647 Lookup finds for the tag formats a bare value of their kind, and the tag takes that
//! entry's direction; a tag no main entry serves where an argument calls a format has no locale,
//! and a screen showing the module in it refuses it. Its language policy is `Understood`: View §4
//! excludes a credential when no tag matches every array.

use sha2::{Digest, Sha256};
use siros_explain::{
    ArgKind, ArgName, DefinedKey, DefinedModule, Domain, Entry, Explain, Keyed, MetadataDigest,
    ParamKind, ParamName, Presence, checked,
};
use siros_i18n::{
    AsciiKey, Body, DefinedError, DefinedForm, LanguagePolicy, LocaleTag, MainLocale, Part, Variant,
};
use siros_openid4vp::json::Node;

use crate::adhoc::Carried;
use crate::conform::ClaimIndex;
use crate::labels::LabelLimits;
use crate::locale::{ArrayKey, chain, lookup, selectable};
use crate::markdown::{Span, Style, spans};
use crate::metadata::{ClaimMeta, DisplayArray, LabelForm, Localized, ValueType};
use crate::outcome::Outcome;
use crate::render::{Registered, arrays, rulebook_metadata};
use crate::rulebook::PasoType;
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
    DefinedModule::new(PLUGIN, MetadataDigest::new(digest.into()))
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
pub(crate) fn argument(claim: ClaimIndex) -> ParamName {
    ParamName::numbered(checked!(ArgName, "c"), claim.get())
}

/// The name of the argument that tells whether the template entry at `position` of an array is
/// discarded.
pub(crate) fn liveness(position: usize) -> ParamName {
    ParamName::numbered(checked!(ArgName, "e"), position)
}

/// The value of a liveness argument for an entry no absent claim discards.
pub(crate) const LIVE: AsciiKey = checked!(AsciiKey, "live");
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

/// Why a type's metadata does not convert.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "paso.convert")]
pub enum ConvertError {
    /// The metadata breaks Proof Metadata §3, or a value type is unsupported.
    #[error(transparent)]
    Metadata(#[from] Outcome),
    /// The module is no render form: a main entry lacks the format of a typed argument.
    #[error(transparent)]
    Defined(#[from] DefinedError),
    /// A template holds the character the conversion reads its placeholders as.
    #[error("a template holds U+FDD0")]
    Reserved,
    /// A display array holds no entry for a language the converted module supports.
    #[error("a display array holds no entry for {0}")]
    NoEntry(#[explain(name = "locale")] LocaleTag),
    /// A display array mixes the wallet's own labels with the metadata's.
    #[error("a display array mixes the wallet's own labels with the metadata's")]
    MixedOwn,
}

/// The defined modules of the ad-hoc metadata a DC API request's entries carry (Proof Metadata
/// §5), as the matcher reads them, unverified, converted as [`convert`] converts a type's
/// metadata, each once, over the main module's entries its registration's package holds.
/// Metadata that does not convert gives no module: the profile's binding refuses its entry.
///
/// # Errors
///
/// [`ConvertError::Defined`]: a main entry lacks a format a converted message calls.
pub fn carried(
    carried: &Carried<'_>,
    main: &[MainLocale],
    priority: &[LocaleTag],
) -> Result<Vec<DefinedForm>, ConvertError> {
    converted(carried.jwts(), main, priority)
}

/// The defined modules of the ad-hoc metadata a request of the URI flow carries, each JWT
/// converted once the wallet verified it for a credential (Proof Metadata §5.3), as [`carried`]
/// converts the matcher's.
///
/// # Errors
///
/// [`ConvertError::Defined`]: a main entry lacks a format a converted message calls.
#[cfg(feature = "resolve")]
pub fn verified(
    verified: &crate::adhoc::Verified<'_>,
    main: &[MainLocale],
    priority: &[LocaleTag],
) -> Result<Vec<DefinedForm>, ConvertError> {
    converted(verified.jwts(), main, priority)
}

/// Each JWT's metadata converted, each module once.
fn converted<'a, 'r: 'a>(
    jwts: impl Iterator<Item = (&'a PasoType<'r>, &'a crate::adhoc::Read<'r>)>,
    main: &[MainLocale],
    priority: &[LocaleTag],
) -> Result<Vec<DefinedForm>, ConvertError> {
    let mut modules: Vec<DefinedForm> = Vec::new();
    for (kind, read) in jwts {
        let registered = Registered::of(kind.clone(), read.metadata());
        match convert(&registered, LabelLimits::PASO, main, priority) {
            Ok(converted) => {
                if modules.iter().all(|known| known.id() != converted.id()) {
                    modules.push(converted);
                }
            }
            Err(defined @ ConvertError::Defined(_)) => return Err(defined),
            Err(
                ConvertError::Metadata(_)
                | ConvertError::Reserved
                | ConvertError::NoEntry(_)
                | ConvertError::MixedOwn,
            ) => {}
        }
    }
    Ok(modules)
}

/// A message's parameters: each argument's name and kind.
type Params = Keyed<ParamName, ParamKind>;

/// An array to convert: what it labels, its entries, and its message's parameters.
struct Converting<'a, 'm> {
    array: ArrayKey,
    entries: &'a DisplayArray<'m>,
    params: Params,
}

/// Converts a type's display rules into its defined module for the End-User's priority list, its
/// typed arguments formatted as the main module's entries `main` format bare values, its labels
/// held to `limits`.
///
/// # Errors
///
/// [`ConvertError`]: its metadata refuses, a template holds U+FDD0, or a main entry lacks a format
/// a message calls.
pub fn convert(
    registered: &Registered<'_>,
    limits: LabelLimits,
    main: &[MainLocale],
    priority: &[LocaleTag],
) -> Result<DefinedForm, ConvertError> {
    let (metadata, _) = rulebook_metadata(registered, limits)?;
    let arrays = arrays(&metadata);
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
    let typed = messages.iter().any(|message| {
        message.params.entries().iter().any(|param| {
            matches!(
                param.value().kind(),
                ArgKind::Date
                    | ArgKind::Time
                    | ArgKind::DateTime
                    | ArgKind::Amount
                    | ArgKind::Currency
            )
        })
    });
    let tags: Vec<LocaleTag> = main.iter().map(|entry| entry.locale().clone()).collect();
    let declaration = Keyed::first_of(
        messages
            .iter()
            .map(|message| Entry::new(key(message.array), message.params.clone())),
    );
    let mut builder = DefinedForm::builder(
        module_of(registered.given()),
        LanguagePolicy::Understood,
        declaration,
    );
    for tag in selectable(&arrays, priority) {
        let entry =
            lookup(&tag, &tags).and_then(|found| main.iter().find(|entry| entry.locale() == found));
        if entry.is_none() && typed {
            continue;
        }
        let bodies = messages
            .iter()
            .map(|message| {
                Ok(Entry::new(
                    key(message.array),
                    message_in(message, &tag, &metadata.claims)?,
                ))
            })
            .collect::<Result<Vec<_>, ConvertError>>()?;
        builder.locale(tag, entry, &Keyed::first_of(bodies))?;
    }
    Ok(builder.finish())
}

/// An array's message in a language: the pattern of the one entry the language takes, or a
/// selection over the liveness of each template entry it takes before its last.
fn message_in(
    message: &Converting<'_, '_>,
    language: &LocaleTag,
    claims: &[ClaimMeta<'_>],
) -> Result<Body, ConvertError> {
    let taken = chain(message.entries, language);
    let patterns = taken
        .iter()
        .map(|(_, entry)| pattern(entry, claims))
        .collect::<Result<Vec<_>, _>>()?;
    let Some((last, before)) = patterns.split_last() else {
        return Err(ConvertError::NoEntry(language.clone()));
    };
    if before.is_empty() {
        return Ok(Body::Pattern(last.clone()));
    }
    let selectors = taken
        .iter()
        .take(before.len())
        .map(|(position, _)| liveness(*position))
        .collect();
    let mut variants: Vec<Variant> = before
        .iter()
        .enumerate()
        .map(|(k, pattern)| Variant {
            keys: (0..before.len())
                .map(|column| (column == k).then_some(LIVE))
                .collect(),
            pattern: pattern.clone(),
        })
        .collect();
    variants.push(Variant {
        keys: vec![None; before.len()],
        pattern: last.clone(),
    });
    Ok(Body::Select {
        selectors,
        variants,
    })
}

/// An entry's label as a pattern.
fn pattern(entry: &Localized<'_>, claims: &[ClaimMeta<'_>]) -> Result<Vec<Part>, ConvertError> {
    Ok(match entry.label {
        LabelForm::Plain(text) => vec![Part::Text(text.as_str().to_owned())],
        LabelForm::Markdown(text) => markup(&spans(text.as_str())),
        LabelForm::Template(text) => template(text, claims)?.0,
        LabelForm::Own(_) => return Err(ConvertError::MixedOwn),
    })
}

/// The styles of a span, outermost first.
fn styles(style: Style) -> impl DoubleEndedIterator<Item = siros_i18n::Style> {
    [
        (Style::STRONG, siros_i18n::Style::Strong),
        (Style::EM, siros_i18n::Style::Emphasis),
        (Style::UNDERLINE, siros_i18n::Style::Underline),
    ]
    .into_iter()
    .filter(move |(bit, _)| style.has(*bit))
    .map(|(_, style)| style)
}

/// Styled spans as parts: each span's text inside markup that opens its styles and closes them.
fn markup(spans: &[Span]) -> Vec<Part> {
    let mut out = Vec::new();
    for span in spans {
        out.extend(styles(span.style).map(Part::Open));
        out.push(Part::Text(span.text.clone()));
        out.extend(styles(span.style).rev().map(Part::Close));
    }
    out
}

/// A `template:mini_markdown` label: its spans with each placeholder naming a claim as that
/// claim's argument, other placeholders literal; and the arguments with their kinds.
fn template(text: &str, claims: &[ClaimMeta<'_>]) -> Result<(Vec<Part>, Params), ConvertError> {
    if text.contains(SLOT) {
        return Err(ConvertError::Reserved);
    }
    let named: Vec<(Placeholder, ClaimIndex)> = placeholders(text)
        .into_iter()
        .filter_map(|placeholder| {
            let index = placeholder.index.filter(|index| *index < claims.len())?;
            Some((placeholder, ClaimIndex(index)))
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
    let mut out = Vec::new();
    for span in spans(&marked) {
        out.extend(styles(span.style).map(Part::Open));
        for (k, part) in span.text.split(SLOT).enumerate() {
            if k > 0
                && let Some(index) = indices.next()
            {
                out.push(Part::Argument(argument(index)));
            }
            if !part.is_empty() {
                out.push(Part::Text(part.to_owned()));
            }
        }
        out.extend(styles(span.style).rev().map(Part::Close));
    }
    let params = named.iter().map(|(_, index)| {
        let value_type = claims
            .get(index.get())
            .and_then(|claim| claim.display.as_ref())
            .map_or(ValueType::Plain, |display| display.value);
        Entry::new(
            argument(*index),
            ParamKind::new(argument_kind(value_type), Presence::Optional),
        )
    });
    Ok((out, Keyed::first_of(params)))
}
