//! A credential's card from its display metadata: the display entry for the wallet's locales and
//! the rows of its claims.

use super::super::{ArrayIndex, ClaimPath, Concrete};
use super::{ClaimsFormat, Display, DisplayItem};
use crate::ids::LocaleTag;
use crate::json::Node;
use siros_explain::{Count, Decimal, Text, Value as Typed};

use crate::rows::{BooleanText, ClaimText, Row, Value, WalletText};
use crate::text::{DisplayText, TextError, lookup};

/// A display array's entry for the wallet's locales, which SD-JWT VC §7 and §8.2 and
/// OpenID4VCI leave to the wallet ("most appropriate"): RFC 4647 Lookup (§3.4) over the priority
/// list, then basic filtering (§3.3.1) over it, then the entry without a locale.
#[must_use]
pub fn format_entry<'n, 'e>(
    entries: &'n [Node<'e>],
    locales: &[LocaleTag],
) -> Option<&'n Node<'e>> {
    let tagged: Vec<(&str, &Node<'e>)> = entries
        .iter()
        .filter_map(|entry| {
            entry
                .get("locale")
                .and_then(Node::as_str)
                .map(|tag| (tag, entry))
        })
        .collect();
    let parsed: Vec<(LocaleTag, &Node<'e>)> = tagged
        .iter()
        .filter_map(|(tag, entry)| LocaleTag::parse(tag).ok().map(|tag| (tag, *entry)))
        .collect();
    let looked_up = locales
        .iter()
        .flat_map(LocaleTag::truncations)
        .find_map(|range| {
            parsed
                .iter()
                .find(|(tag, _)| *tag == range)
                .map(|(_, entry)| *entry)
        });
    let tags: Vec<&str> = tagged.iter().map(|(tag, _)| *tag).collect();
    let filtered = || {
        locales.iter().find_map(|locale| {
            lookup(locale, &tags).and_then(|tag| {
                tagged
                    .iter()
                    .find(|(t, _)| t == tag)
                    .map(|(_, entry)| *entry)
            })
        })
    };
    let untagged = || entries.iter().find(|entry| entry.get("locale").is_none());
    looked_up.or_else(filtered).or_else(untagged)
}

/// The view's `byte_strings`: where its `values` hold a byte string RFC 8949 §6.1 wrote as text,
/// with its length in bytes. [`ClaimsView`](super::ClaimsView) reads their shape.
pub(super) fn byte_strings<'v, 'a>(view: &'v Node<'a>) -> &'v [Node<'a>] {
    view.get("byte_strings")
        .and_then(Node::as_array)
        .unwrap_or(&[])
}

/// The length of the byte string at `path`; `None` for another value.
fn byte_length(strings: &[Node<'_>], path: &[Concrete<'_>]) -> Option<Count> {
    let same = |written: &[Node<'_>]| {
        written.len() == path.len()
            && written.iter().zip(path).all(|(step, at)| match (step, at) {
                (Node::String(name), Concrete::Key(key)) => name == key,
                (Node::Number(index), Concrete::Index(at)) => {
                    index.as_u64() == u64::try_from(at.position()).ok()
                }
                _ => false,
            })
    };
    let found = strings.iter().find(|string| {
        string
            .get("path")
            .and_then(Node::as_array)
            .is_some_and(same)
    })?;
    match found.get("length")? {
        Node::Number(length) => Count::parse(length.text()),
        _ => None,
    }
}

pub(super) fn metadata<'v, 'a>(view: &'v Node<'a>, name: &str) -> &'v [Node<'a>] {
    view.get("metadata")
        .and_then(|metadata| metadata.get(name))
        .and_then(Node::as_array)
        .unwrap_or(&[])
}

/// An entry of the metadata's `claims` with a pointer.
pub(super) struct Described<'v, 'a> {
    pub(super) path: ClaimPath<'v>,
    pub(super) claim: &'v Node<'a>,
    /// Its position in `claims`.
    pub(super) position: usize,
}

fn label_of(
    format: &impl ClaimsFormat,
    path: &[Concrete<'_>],
    described: &[Described<'_, '_>],
    display: Display<'_>,
) -> Result<Option<Text>, TextError> {
    let Some(found) = described.iter().find(|known| known.path.matches(path)) else {
        return Ok(None);
    };
    let entry = format_entry(
        found
            .claim
            .get("display")
            .and_then(Node::as_array)
            .unwrap_or(&[]),
        display.locales,
    );
    entry
        .and_then(|entry| entry.get(format.label_key()))
        .and_then(Node::as_str)
        .map_or(Ok(None), |name| {
            display.label(format, DisplayItem::Claim(found.position), name)
        })
}

/// A label that shows as written; `None` for white space alone, which the wallet's word or a
/// member name then stands for.
pub(super) fn label_text(text: &str) -> Result<Option<Text>, TextError> {
    match DisplayText::label(text) {
        Ok(label) => Ok(Some(Text::Raw(label.into_string()))),
        Err(TextError::Empty) => Ok(None),
        Err(refused) => Err(refused),
    }
}

/// Reads each text under a view's `metadata` through [`DisplayText`], whatever its language: the
/// members `name`, `alt_text` and the format's label as labels, `description` as a value. The
/// other members are no text the End-User reads.
pub(super) fn metadata_texts(format: &impl ClaimsFormat, node: &Node<'_>) -> Result<(), TextError> {
    match node {
        Node::Object(object) => object.members().iter().try_for_each(|member| {
            match (member.name.as_ref(), member.value.as_str()) {
                ("description", Some(text)) => DisplayText::value(text).map(drop),
                ("name" | "alt_text", Some(text)) => label_text(text).map(drop),
                (name, Some(text)) if name == format.label_key() => label_text(text).map(drop),
                _ => metadata_texts(format, &member.value),
            }
        }),
        Node::Array(items) => items
            .iter()
            .try_for_each(|item| metadata_texts(format, item)),
        _ => Ok(()),
    }
}

/// The label of a claim without one in the metadata: its last member name, or the wallet's word
/// for a claim when its path names no member or that name is white space alone.
fn fallback_label(path: &[Concrete<'_>]) -> Result<Text, TextError> {
    let name = path.iter().rev().find_map(|step| match step {
        Concrete::Key(key) => Some(key),
        Concrete::Index(_) => None,
    });
    Ok(name
        .map_or(Ok(None), |name| label_text(name))?
        .unwrap_or_else(|| Text::of(&WalletText::Claim)))
}

/// An object is a heading row then its members; an array of values gives each element the
/// array's label; an array holding objects or arrays is a heading row then its elements. A claim
/// without a label in the metadata shows its last member name, or the wallet's word for a claim
/// when its path names no member. A scalar value shows by its type: a boolean as the wallet's yes
/// or no, `null` as the wallet's text for no value, a number as a count or an exact decimal and
/// beyond those as the JSON text the credential wrote, a byte string by its length. The labels and
/// names read through [`DisplayText`]; the credential's strings show as written.
pub(super) fn value_rows(
    format: &impl ClaimsFormat,
    path: &[Concrete<'_>],
    value: &Node<'_>,
    described: &[Described<'_, '_>],
    display: Display<'_>,
    inherited: Option<&Text>,
) -> Result<Vec<Row>, TextError> {
    let label = label_of(format, path, described, display)?.or_else(|| inherited.cloned());
    let child = |step: Concrete<'_>| -> Vec<Concrete<'_>> {
        path.iter()
            .map(Concrete::to_owned_step)
            .chain(std::iter::once(step.to_owned_step()))
            .collect()
    };
    let text = match value {
        Node::Object(object) => {
            let mut rows: Vec<Row> = label.map(Row::full_text).into_iter().collect();
            for member in object.members() {
                let step = child(Concrete::Key(member.name.clone()));
                rows.extend(value_rows(
                    format,
                    &step,
                    &member.value,
                    described,
                    display,
                    None,
                )?);
            }
            return Ok(rows);
        }
        Node::Array(items) => {
            let shown: Vec<(usize, &Node<'_>)> = items
                .iter()
                .enumerate()
                .filter(|(_, item)| !format.withheld(item))
                .collect();
            let nested = shown
                .iter()
                .any(|(_, item)| matches!(item, Node::Object(_) | Node::Array(_)));
            let mut rows = Vec::new();
            let passed = if nested {
                rows.extend(label.map(Row::full_text));
                None
            } else if shown.is_empty() {
                label
            } else {
                Some(label.map_or_else(|| fallback_label(path), Ok)?)
            };
            for (at, item) in shown {
                let step = child(Concrete::Index(ArrayIndex::new(at)));
                rows.extend(value_rows(
                    format,
                    &step,
                    item,
                    described,
                    display,
                    passed.as_ref(),
                )?);
            }
            return Ok(rows);
        }
        Node::Bool(true) => Text::of(&BooleanText::Yes),
        Node::Bool(false) => Text::of(&BooleanText::No),
        Node::Null => Text::of(&WalletText::Null),
        Node::Number(number) => number_value(number.text())
            .map_or_else(|| Text::Raw(number.text().to_owned()), Text::Value),
        Node::String(written) => byte_length(display.byte_strings, path).map_or_else(
            || Text::Raw(written.to_string()),
            |length| Text::of(&ClaimText::Bytes { length }),
        ),
    };
    Ok(vec![Row::new(
        label.map_or_else(|| fallback_label(path), Ok)?,
        Value::Text(text),
    )])
}

/// A JSON number (RFC 8259 §6) as an exact value: a natural number as a count, another as a
/// decimal; `None` beyond a decimal's 38 fraction digits or an `i128`'s units.
fn number_value(text: &str) -> Option<Typed> {
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().ok()?),
        None => (text, 0),
    };
    let (negative, unsigned) = match mantissa.strip_prefix('-') {
        Some(unsigned) => (true, unsigned),
        None => (false, mantissa),
    };
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    let scale = i32::try_from(fraction.len()).ok()? - exponent;
    let mut digits = format!("{whole}{fraction}");
    if scale < 0 {
        let zeros = usize::try_from(-scale).ok().filter(|zeros| *zeros <= 38)?;
        digits.push_str(&"0".repeat(zeros));
    }
    let scale = u8::try_from(scale.max(0)).ok()?;
    if !negative && scale == 0 {
        return Count::parse(&digits).map(Typed::Count);
    }
    let units: i128 = digits.parse().ok()?;
    Decimal::new(if negative { -units } else { units }, scale).map(Typed::Decimal)
}

impl Concrete<'_> {
    fn to_owned_step(&self) -> Concrete<'static> {
        match self {
            Concrete::Key(key) => Concrete::Key(std::borrow::Cow::Owned(key.to_string())),
            Concrete::Index(at) => Concrete::Index(*at),
        }
    }
}
