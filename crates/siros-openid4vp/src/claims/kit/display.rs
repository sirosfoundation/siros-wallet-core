//! A credential's card from its display metadata: the display entry for the wallet's locales and
//! the rows of its claims.

use super::super::{ClaimPath, Concrete};
use super::{ClaimsFormat, text_of};
use crate::ids::LocaleTag;
use crate::json::Node;
use siros_explain::{Count, Decimal, Text, Value as Typed};

use crate::rows::{BooleanText, Row, Value, WalletText};
use crate::text::{DisplayText, TextError, lookup};

/// A display array's entry for the wallet's locales, which SD-JWT VC §7 and §8.2 and
/// OpenID4VCI leave to the wallet ("most appropriate"): RFC 4647 basic filtering over the priority
/// list, the entry equal to a tag else the first extending it, then the entry without a locale,
/// then the first entry.
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
    let tags: Vec<&str> = tagged.iter().map(|(tag, _)| *tag).collect();
    let matched = locales.iter().find_map(|locale| {
        lookup(locale, &tags).and_then(|tag| {
            tagged
                .iter()
                .find(|(t, _)| t == tag)
                .map(|(_, entry)| *entry)
        })
    });
    let untagged = || entries.iter().find(|entry| entry.get("locale").is_none());
    matched.or_else(untagged).or_else(|| entries.first())
}

pub(super) fn metadata<'v, 'a>(view: &'v Node<'a>, name: &str) -> &'v [Node<'a>] {
    view.get("metadata")
        .and_then(|metadata| metadata.get(name))
        .and_then(Node::as_array)
        .unwrap_or(&[])
}

fn label_of(
    format: &impl ClaimsFormat,
    path: &[Concrete<'_>],
    described: &[(ClaimPath<'_>, &Node<'_>)],
    locales: &[LocaleTag],
) -> Result<Option<Text>, TextError> {
    let Some((_, claim)) = described.iter().find(|(pointer, _)| pointer.matches(path)) else {
        return Ok(None);
    };
    let entry = format_entry(
        claim.get("display").and_then(Node::as_array).unwrap_or(&[]),
        locales,
    );
    entry
        .and_then(|entry| entry.get(format.label_key()))
        .and_then(Node::as_str)
        .map_or(Ok(None), label_text)
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
/// when its path names no member; a non-string value its JSON text. The labels and names read
/// through [`DisplayText`]; the credential's values show as written.
pub(super) fn value_rows(
    format: &impl ClaimsFormat,
    path: &[Concrete<'_>],
    value: &Node<'_>,
    described: &[(ClaimPath<'_>, &Node<'_>)],
    locales: &[LocaleTag],
    inherited: Option<&Text>,
) -> Result<Vec<Row>, TextError> {
    let label = label_of(format, path, described, locales)?.or_else(|| inherited.cloned());
    let child = |step: Concrete<'_>| -> Vec<Concrete<'_>> {
        path.iter()
            .map(Concrete::to_owned_step)
            .chain(std::iter::once(step.to_owned_step()))
            .collect()
    };
    let mut rows = Vec::new();
    match value {
        Node::Object(object) => {
            rows.extend(label.map(Row::full_text));
            for member in object.members() {
                let step = child(Concrete::Key(member.name.clone()));
                rows.extend(value_rows(
                    format,
                    &step,
                    &member.value,
                    described,
                    locales,
                    None,
                )?);
            }
        }
        Node::Array(items) => {
            let nested = items
                .iter()
                .any(|item| matches!(item, Node::Object(_) | Node::Array(_)));
            let passed = if nested {
                rows.extend(label.map(Row::full_text));
                None
            } else if items.is_empty() {
                label
            } else {
                Some(label.map_or_else(|| fallback_label(path), Ok)?)
            };
            for (at, item) in items.iter().enumerate() {
                let step = child(Concrete::Index(at));
                rows.extend(value_rows(
                    format,
                    &step,
                    item,
                    described,
                    locales,
                    passed.as_ref(),
                )?);
            }
        }
        scalar => rows.push(Row::new(
            label.map_or_else(|| fallback_label(path), Ok)?,
            Value::Text(scalar_text(scalar)),
        )),
    }
    Ok(rows)
}

/// A claim's scalar value as its type shows it: a boolean as the wallet's yes or no, `null` as
/// the wallet's text for no value, a number as a count or an exact decimal, a string as written.
fn scalar_text(node: &Node<'_>) -> Text {
    match node {
        Node::Bool(true) => Text::of(&BooleanText::Yes),
        Node::Bool(false) => Text::of(&BooleanText::No),
        Node::Null => Text::of(&WalletText::Null),
        Node::Number(number) => {
            number_value(number.text()).map_or_else(|| Text::Raw(text_of(node)), Text::Value)
        }
        _ => Text::Raw(text_of(node)),
    }
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
