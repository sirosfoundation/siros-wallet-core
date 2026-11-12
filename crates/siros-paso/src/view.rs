//! PaSO View's display rules as MessageFormat 2 resource source: the conversion the wallet runs
//! when a type's metadata loads, and the matcher when ad-hoc metadata arrives with a request, and
//! the ids phase 1's texts name.
//!
//! A conversion is one resource in the context's locale. Each tag of the End-User's priority list
//! that View §4 can select is a section `paso.view.<digest>.<tag>`, `<digest>` the hexadecimal
//! SHA-256 of the metadata's compact JSON ([`ViewId`]), so conversions of several types load into
//! one context. In it, each display array is one message under the key of what it labels: a
//! claim's `claim_<k>`, a UI label's name. An array's message is the text of the entries View §4
//! tries for that tag: one entry's, or for a template that an absent claim discards, a `.match`
//! over each such entry's argument `e<j>` (`live` or `dead`, by its position) whose fallback is
//! the last entry tried. A plain label is literal text, a `mini_markdown` label its emphasis,
//! strong and underline spans as markup (`strong`, `emphasis`, `underline`), a template label its
//! spans with each `{n}` naming a claim as the argument `c<n>`, formatted by claim n's value type:
//! `:siros:date`, `:siros:time` and `:siros:datetime` over the value's literal, `:currency` over
//! an amount's number `c<n>` with its code `c<n>_currency`, any other value as given. Every text
//! the metadata writes reaches the source through [`siros_i18n::escape`]. A message's format
//! options are the wallet's modules' in the same context.
//!
//! Every id, name and variant key the source holds is ASCII: digests, language tags,
//! `claim_<n>`, UI labels' names, `c<n>`, `c<n>_currency`, `e<j>`, `live`, and the functions' and
//! the markup's names. A matcher whose siros-i18n is built without `nfc` loads the source into the
//! messages the wallet loads.

use sha2::{Digest, Sha256};
use siros_explain::Explain;
use siros_i18n::{Arg, Context, LoadError, LocaleTag, Message, ResolveError, escape};
use siros_openid4vp::json::Node;

use crate::adhoc::Carried;
use crate::conform::ClaimIndex;
use crate::labels::LabelLimits;
use crate::locale::{ArrayKey, chain, selectable};
use crate::markdown::{Span, Style, spans};
use crate::metadata::{ClaimMeta, DisplayArray, LabelForm, Localized, RESERVED, ValueType};
use crate::outcome::Outcome;
use crate::render::{Registered, arrays, rulebook_metadata};
use crate::rulebook::PasoType;
use crate::template::marked;
use crate::value::{FormattedKind, ValueKind};

/// The prefix of the ids a type's metadata converts to: `paso.view.` and the hexadecimal SHA-256
/// of the metadata's compact JSON.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ViewId(String);

impl ViewId {
    /// The prefix of a type's metadata.
    #[must_use]
    pub fn of(given: &Node<'_>) -> Self {
        let digest = Sha256::digest(given.json_compact().to_string().as_bytes());
        let mut id = String::from("paso.view.");
        for byte in digest {
            id.push_str(&format!("{byte:02x}"));
        }
        Self(id)
    }

    /// The prefix.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The id of an array's message in the section of `tag`.
    pub(crate) fn message(&self, tag: &LocaleTag, array: ArrayKey) -> String {
        format!("{}.{tag}.{}", self.0, key(array))
    }
}

/// The key of a display array's message: `claim_<index>` for a claim's, the UI label's name for
/// a UI label's.
fn key(array: ArrayKey) -> String {
    match array {
        ArrayKey::Claim(claim) => format!("claim_{}", claim.get()),
        ArrayKey::Ui(ui) => ui.name().to_owned(),
    }
}

/// The name of the argument a template's `{n}` gives claim n's value under; an amount's number.
pub(crate) fn argument(claim: ClaimIndex) -> String {
    format!("c{}", claim.get())
}

/// The name of the argument that gives claim n's amount's currency.
pub(crate) fn currency(claim: ClaimIndex) -> String {
    format!("c{}_currency", claim.get())
}

/// The name of the argument that tells whether the template entry at `position` of an array is
/// discarded.
pub(crate) fn liveness(position: usize) -> String {
    format!("e{position}")
}

/// The value of a liveness argument for an entry no absent claim discards.
pub(crate) const LIVE: &str = "live";
/// The value of a liveness argument for an entry an absent claim discards.
pub(crate) const DEAD: &str = "dead";

/// How a template's `{n}` shows claim n's value, by the claim's value type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shows {
    /// As given: a text, a boolean or a frequency as the wallet words it, a currency's code.
    Given,
    /// Through a function of the value's literal.
    Function(&'static str),
    /// Through `:currency`: the amount's number with its code as the `currency` option.
    Amount,
}

const fn shows(value_type: ValueType) -> Shows {
    match value_type {
        ValueType::Kind(ValueKind::Formatted(kind)) => match kind {
            FormattedKind::Date => Shows::Function("siros:date"),
            FormattedKind::Time => Shows::Function("siros:time"),
            FormattedKind::DateTime => Shows::Function("siros:datetime"),
            FormattedKind::CurrencyAmount => Shows::Amount,
            FormattedKind::Text
            | FormattedKind::Boolean
            | FormattedKind::Frequency
            | FormattedKind::Currency
            | FormattedKind::MiniMarkdown
            | FormattedKind::Url => Shows::Given,
        },
        ValueType::Plain
        | ValueType::Kind(ValueKind::Image)
        | ValueType::LabelOnly
        | ValueType::Template(_) => Shows::Given,
    }
}

/// Why a type's metadata does not convert.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum ConvertError {
    /// The metadata breaks Proof Metadata §3, or a value type or a template label is unsupported.
    #[error(transparent)]
    Metadata(#[from] Outcome),
    /// The converted source does not load into the context: a function the build lacks, format
    /// options no module of the context defines.
    #[error(transparent)]
    Load(#[from] LoadError),
    /// The context holds no module, so no locale to write the source in.
    #[error("the context holds no module")]
    #[explain(id = "convert.unlocalized")]
    Unlocalized,
    /// A display array holds no entry for a language the conversion supports.
    #[error("a display array holds no entry for {locale}")]
    #[explain(id = "convert.no_entry")]
    NoEntry {
        /// The language.
        locale: LocaleTag,
    },
    /// A display array mixes the wallet's own labels with the metadata's.
    #[error("a display array mixes the wallet's own labels with the metadata's")]
    #[explain(id = "convert.mixed_own")]
    MixedOwn,
    /// Reading a template label's `mini_markdown` kept other than one placeholder mark per
    /// placeholder.
    #[error("a template label's mini_markdown lost a placeholder")]
    #[explain(id = "convert.slots")]
    Slots,
    /// `siros_i18n::escape` wrote no quoted pattern.
    #[error("escape wrote no quoted pattern")]
    #[explain(id = "convert.unquoted")]
    Unquoted,
}

/// The sources of the ad-hoc metadata a DC API request's entries carry (Proof Metadata §5), as
/// the matcher reads them, unverified, converted as [`convert`] converts a type's metadata, each
/// metadata once, none the context words already. Metadata that does not convert gives no
/// source: the profile's binding refuses its entry.
///
/// # Errors
///
/// [`ConvertError`] other than [`ConvertError::Metadata`]: a converted source does not load into
/// the context.
pub fn carried(
    carried: &Carried<'_>,
    context: &Context,
    priority: &[LocaleTag],
) -> Result<Vec<String>, ConvertError> {
    converted(carried.jwts(), context, priority)
}

/// The sources of the ad-hoc metadata a request of the URI flow carries, each JWT converted once
/// the wallet verified it for a credential (Proof Metadata §5.3), as [`carried`] converts the
/// matcher's.
///
/// # Errors
///
/// [`ConvertError`] other than [`ConvertError::Metadata`]: a converted source does not load into
/// the context.
#[cfg(feature = "resolve")]
pub fn verified(
    verified: &crate::adhoc::Verified<'_>,
    context: &Context,
    priority: &[LocaleTag],
) -> Result<Vec<String>, ConvertError> {
    converted(verified.jwts(), context, priority)
}

/// Each JWT's metadata converted, each source once, each loaded after the ones before it.
fn converted<'a, 'r: 'a>(
    jwts: impl Iterator<Item = (&'a PasoType<'r>, &'a crate::adhoc::Read<'r>)>,
    context: &Context,
    priority: &[LocaleTag],
) -> Result<Vec<String>, ConvertError> {
    let mut running = context.clone();
    let mut sources: Vec<String> = Vec::new();
    for (kind, read) in jwts {
        let registered = Registered::of(kind.clone(), read.metadata());
        let conversion = match written(&registered, LabelLimits::PASO, &running, priority) {
            Ok(conversion) => conversion,
            Err(ConvertError::Metadata(_)) => continue,
            Err(other) => return Err(other),
        };
        let Some(first) = &conversion.first else {
            continue;
        };
        if words(&running, first) {
            continue;
        }
        running = running.module(&conversion.source)?;
        sources.push(conversion.source);
    }
    Ok(sources)
}

/// Converts a type's display rules into a resource of the context's locale for the End-User's
/// priority list, its labels held to `limits`, and checks that it loads into the context.
///
/// # Errors
///
/// [`ConvertError`]: its metadata refuses, the context holds no module, or the source does not
/// load into the context.
pub fn convert(
    registered: &Registered<'_>,
    limits: LabelLimits,
    context: &Context,
    priority: &[LocaleTag],
) -> Result<String, ConvertError> {
    let conversion = written(registered, limits, context, priority)?;
    context.clone().module(&conversion.source).map(drop)?;
    Ok(conversion.source)
}

/// The context with a type's converted source loaded, as [`convert`] writes it.
pub(crate) fn load(
    registered: &Registered<'_>,
    limits: LabelLimits,
    context: &Context,
    priority: &[LocaleTag],
) -> Result<Context, ConvertError> {
    let conversion = written(registered, limits, context, priority)?;
    Ok(context.clone().module(&conversion.source)?)
}

/// Whether the context words `id`: a message of that id resolves, or fails for a reason other
/// than its id.
pub(crate) fn words(context: &Context, id: &str) -> bool {
    !matches!(
        context.resolve(&Probe(id)),
        Err(ResolveError::Unknown { .. })
    )
}

/// A message of an id, without arguments.
struct Probe<'i>(&'i str);

impl Message for Probe<'_> {
    fn id(&self) -> &str {
        self.0
    }

    fn arg(&self, _key: &str) -> Option<&dyn Arg> {
        None
    }
}

/// A converted source, and the id of its first message.
struct Conversion {
    source: String,
    first: Option<String>,
}

/// Writes the source.
fn written(
    registered: &Registered<'_>,
    limits: LabelLimits,
    context: &Context,
    priority: &[LocaleTag],
) -> Result<Conversion, ConvertError> {
    let locale = context.locale().ok_or(ConvertError::Unlocalized)?;
    let (metadata, _) = rulebook_metadata(registered, limits)?;
    let arrays = arrays(&metadata);
    let converting: Vec<&(ArrayKey, &DisplayArray<'_>)> = arrays
        .iter()
        .filter(|(_, entries)| {
            !entries
                .entries()
                .iter()
                .all(|entry| matches!(entry.label, LabelForm::Own(_)))
        })
        .collect();
    let view = ViewId::of(registered.given());
    let mut source = format!("@locale {locale}\n---\n");
    let mut first = None;
    for tag in selectable(&arrays, priority) {
        if converting.is_empty() {
            break;
        }
        source.push_str(&format!("\n[{}.{tag}]\n", view.as_str()));
        for (array, entries) in &converting {
            if first.is_none() {
                first = Some(view.message(&tag, *array));
            }
            let message = message_in(entries, &tag, &metadata.claims)?;
            source.push_str(&format!("{} = {message}\n", key(*array)));
        }
    }
    Ok(Conversion { source, first })
}

/// An array's message in a language: the pattern of the one entry the language takes, or a
/// `.match` over the liveness of each template entry it takes before its last.
fn message_in(
    array: &DisplayArray<'_>,
    language: &LocaleTag,
    claims: &[ClaimMeta<'_>],
) -> Result<String, ConvertError> {
    let taken = chain(array, language);
    let patterns = taken
        .iter()
        .map(|(_, entry)| pattern(entry, claims))
        .collect::<Result<Vec<_>, _>>()?;
    let Some((last, before)) = patterns.split_last() else {
        return Err(ConvertError::NoEntry {
            locale: language.clone(),
        });
    };
    if before.is_empty() {
        return Ok(last.clone());
    }
    let selectors: Vec<String> = taken
        .iter()
        .take(before.len())
        .map(|(position, _)| liveness(*position))
        .collect();
    let mut message = String::new();
    for selector in &selectors {
        message.push_str(&format!(".input {{${selector} :string}} "));
    }
    message.push_str(".match");
    for selector in &selectors {
        message.push_str(&format!(" ${selector}"));
    }
    for (k, pattern) in before.iter().enumerate() {
        for column in 0..before.len() {
            message.push(' ');
            message.push_str(if column == k { LIVE } else { "*" });
        }
        message.push(' ');
        message.push_str(pattern);
    }
    for _ in before {
        message.push_str(" *");
    }
    message.push(' ');
    message.push_str(last);
    Ok(message)
}

/// An entry's label as a quoted pattern.
fn pattern(entry: &Localized<'_>, claims: &[ClaimMeta<'_>]) -> Result<String, ConvertError> {
    Ok(match entry.label {
        LabelForm::Plain(text) => escape(text.as_str()),
        LabelForm::Markdown(text) => quoted(&markup(&spans(text.as_str()))?),
        LabelForm::Template(text) => quoted(&template(text, claims)?),
        LabelForm::Own(_) => return Err(ConvertError::MixedOwn),
    })
}

/// A pattern's text as a quoted pattern.
fn quoted(body: &str) -> String {
    format!("{{{{{body}}}}}")
}

/// Text from the metadata as a pattern's literal text: [`escape`]'s quoted pattern without its
/// quotes.
fn literal(text: &str) -> Result<String, ConvertError> {
    escape(text)
        .strip_prefix("{{")
        .and_then(|body| body.strip_suffix("}}"))
        .map(str::to_owned)
        .ok_or(ConvertError::Unquoted)
}

/// The markup names of a span's styles, outermost first.
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

/// Styled spans as a pattern's text: each span's literal text inside markup that opens its styles
/// and closes them.
fn markup(spans: &[Span]) -> Result<String, ConvertError> {
    let mut out = String::new();
    for span in spans {
        open(&mut out, span.style);
        out.push_str(&literal(&span.text)?);
        close(&mut out, span.style);
    }
    Ok(out)
}

/// Opens a span's styles.
fn open(out: &mut String, style: Style) {
    for name in styles(style) {
        out.push_str(&format!("{{#{name}}}"));
    }
}

/// Closes a span's styles.
fn close(out: &mut String, style: Style) {
    for name in styles(style).rev() {
        out.push_str(&format!("{{/{name}}}"));
    }
}

/// A `template:mini_markdown` label as a pattern's text: its spans with each placeholder naming a
/// claim as that claim's argument, other placeholders literal.
fn template(text: &str, claims: &[ClaimMeta<'_>]) -> Result<String, ConvertError> {
    let (marked, named) = marked(text, claims);
    let mut indices = named.into_iter();
    let mut out = String::new();
    for span in spans(&marked) {
        open(&mut out, span.style);
        for (k, piece) in span.text.split(RESERVED).enumerate() {
            if k > 0 {
                let index = indices.next().ok_or(ConvertError::Slots)?;
                out.push_str(&placeholder(index, value_type(claims, index)));
            }
            out.push_str(&literal(piece)?);
        }
        close(&mut out, span.style);
    }
    if indices.next().is_some() {
        return Err(ConvertError::Slots);
    }
    Ok(out)
}

/// A claim's value type: a claim without `display` has none.
fn value_type(claims: &[ClaimMeta<'_>], claim: ClaimIndex) -> ValueType {
    claims
        .get(claim.get())
        .and_then(|claim| claim.display.as_ref())
        .map_or(ValueType::Plain, |display| display.value)
}

/// The placeholder of claim n's argument, as its value type shows it.
fn placeholder(claim: ClaimIndex, value_type: ValueType) -> String {
    let name = argument(claim);
    match shows(value_type) {
        Shows::Given => format!("{{${name}}}"),
        Shows::Function(function) => format!("{{${name} :{function}}}"),
        Shows::Amount => format!("{{${name} :currency currency=${}}}", currency(claim)),
    }
}
