//! A credential's card from its display metadata: the display entry for the wallet's locales and
//! the rows of its claims.

use super::super::{ClaimPath, Concrete};
use super::{ClaimsFormat, Display, DisplayItem, text_of};
use crate::ids::LocaleTag;
use crate::json::Node;
use siros_explain::{Count, Decimal, Text, Value as Typed};

use crate::rows::{BooleanText, Row, Value, WalletText};
use crate::text::lookup;
use crate::text::python_space;

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
) -> Option<Text> {
    let found = described.iter().find(|known| known.path.matches(path))?;
    let entry = format_entry(
        found
            .claim
            .get("display")
            .and_then(Node::as_array)
            .unwrap_or(&[]),
        display.locales,
    )?;
    entry
        .get(format.label_key())
        .and_then(Node::as_str)
        .filter(|name| !name.trim_matches(python_space).is_empty())
        .map(|name| display.text(format, DisplayItem::Claim(found.position), name))
}

/// An object is a heading row then its members; an array of values gives each element the
/// array's label; an array holding objects or arrays is a heading row then its elements. A claim
/// without a label in the metadata shows its last member name, or the wallet's word for a claim
/// when its path names no member; a non-string value its JSON text. The issuer's labels and the
/// credential's names and values show as written.
pub(super) fn value_rows(
    format: &impl ClaimsFormat,
    path: &[Concrete<'_>],
    value: &Node<'_>,
    described: &[Described<'_, '_>],
    display: Display<'_>,
    inherited: Option<&Text>,
) -> Vec<Row> {
    let label = label_of(format, path, described, display).or_else(|| inherited.cloned());
    let fallback = path
        .iter()
        .rev()
        .find_map(|step| match step {
            Concrete::Key(key) => Some(Text::Raw(key.to_string())),
            Concrete::Index(_) => None,
        })
        .unwrap_or_else(|| Text::of(&WalletText::Claim));
    let child = |step: Concrete<'_>| -> Vec<Concrete<'_>> {
        path.iter()
            .map(Concrete::to_owned_step)
            .chain(std::iter::once(step.to_owned_step()))
            .collect()
    };
    match value {
        Node::Object(object) => label
            .map(Row::full_text)
            .into_iter()
            .chain(object.members().iter().flat_map(|member| {
                value_rows(
                    format,
                    &child(Concrete::Key(member.name.clone())),
                    &member.value,
                    described,
                    display,
                    None,
                )
            }))
            .collect(),
        Node::Array(items) => {
            let nested = items.iter().any(|item| {
                matches!(item, Node::Object(_) | Node::Array(_)) && !format.withheld(item)
            });
            let head = label.clone().filter(|_| nested).map(Row::full_text);
            let passed = (!nested).then(|| label.unwrap_or_else(|| fallback.clone()));
            head.into_iter()
                .chain(
                    items
                        .iter()
                        .enumerate()
                        .filter(|(_, item)| !format.withheld(item))
                        .flat_map(|(at, item)| {
                            value_rows(
                                format,
                                &child(Concrete::Index(at)),
                                item,
                                described,
                                display,
                                passed.as_ref(),
                            )
                        }),
                )
                .collect()
        }
        scalar => vec![Row::new(
            label.unwrap_or(fallback),
            Value::Text(scalar_text(scalar)),
        )],
    }
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
