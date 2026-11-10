//! A credential's card from its display metadata: the display entry for the wallet's locales and
//! the rows of its claims.

use siros_syntax::{Count, Date, DateTime, Decimal, Fraction, Malformed, Offset, Second, Time};

use super::super::{ArrayIndex, Concrete};
use super::{CardError, ClaimEntry, ClaimsFormat, Display};
use crate::ids::LocaleTag;
use crate::json::Node;
use crate::rows::{BooleanText, ClaimText, ExactNumber, WalletText};
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

/// An entry of the view's `byte_strings` or `dates`: the `path` of a string of its `values`, and
/// what the string holds.
#[derive(Debug, Clone)]
pub(crate) struct Located<'v, T> {
    pub(crate) path: Vec<Node<'v>>,
    pub(crate) held: T,
}

impl<'v, T> Located<'v, T> {
    /// The entry an element of the view's `byte_strings` or `dates` writes: an object with a
    /// `path` array and what `held` reads of it.
    pub(super) fn read(entry: Node<'v>, held: impl Fn(&Node<'v>) -> Option<T>) -> Option<Self> {
        let held = held(&entry)?;
        let Node::Object(mut entry) = entry else {
            return None;
        };
        match entry.take("path") {
            Some(Node::Array(path)) => Some(Self { path, held }),
            _ => None,
        }
    }
}

/// The length an entry of the view's `byte_strings` states: a byte string RFC 8949 §6.1 wrote as
/// text has that many bytes.
pub(super) fn length_of(entry: &Node<'_>) -> Option<Count> {
    match entry.get("length") {
        Some(Node::Number(length)) => Count::parse(length.text()).ok(),
        _ => None,
    }
}

/// The number `digits` write; `None` for another byte or past a `u16`.
fn number(digits: &[u8]) -> Option<u16> {
    digits.iter().try_fold(0u16, |value, digit| {
        if !digit.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u16::from(digit - b'0'))
    })
}

/// The date of a `full-date`, `YYYY-MM-DD` (RFC 8943; RFC 3339 §5.6).
#[must_use]
pub fn full_date(text: &str) -> Option<Date> {
    let [y1, y2, y3, y4, b'-', m1, m2, b'-', d1, d2] = *text.as_bytes() else {
        return None;
    };
    Date::new(
        number(&[y1, y2, y3, y4])?,
        u8::try_from(number(&[m1, m2])?).ok()?,
        u8::try_from(number(&[d1, d2])?).ok()?,
    )
}

/// The date and time of a `tdate` of the form `YYYY-MM-DDThh:mm:ssZ` (RFC 8949 §3.4.1; ISO/IEC
/// 18013-5 §9.1.2.4: no fraction, no offset but `Z`).
#[must_use]
pub fn tdate(text: &str) -> Option<DateTime> {
    let (date, time) = text.split_once('T')?;
    let [h1, h2, b':', m1, m2, b':', s1, s2, b'Z'] = *time.as_bytes() else {
        return None;
    };
    let second = Second::new(u8::try_from(number(&[s1, s2])?).ok()?, Fraction::NONE)?;
    let at = Time::new(
        u8::try_from(number(&[h1, h2])?).ok()?,
        u8::try_from(number(&[m1, m2])?).ok()?,
        Some(second),
    )?;
    Some(DateTime::new(full_date(date)?, at, Some(Offset::new(0)?)))
}

/// The text of an entry of the view's `dates`: its `date`, a `full-date` or a `tdate`.
pub(super) fn date_of(entry: &Node<'_>) -> Option<ClaimText> {
    let text = entry.get("date")?.as_str()?;
    full_date(text)
        .map(|value| ClaimText::Date { value })
        .or_else(|| tdate(text).map(|value| ClaimText::DateTime { value }))
}

/// What the entry of `entries` whose `path` is `path` holds.
fn entry_at<'e, T>(entries: &'e [Located<'_, T>], path: &[Concrete<'_>]) -> Option<&'e T> {
    let same = |written: &[Node<'_>]| {
        written.len() == path.len()
            && written.iter().zip(path).all(|(step, at)| match (step, at) {
                (Node::String(name), Concrete::Key(key)) => name == key,
                (Node::Number(index), Concrete::Index(at)) => {
                    index.as_u64().map(usize::try_from) == Some(Ok(at.position()))
                }
                _ => false,
            })
    };
    entries
        .iter()
        .find(|entry| same(&entry.path))
        .map(|entry| &entry.held)
}

/// A text of a card, which the context resolves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Said {
    /// A text of the wallet's.
    Wallet(WalletText),
    /// A boolean value.
    Boolean(BooleanText),
    /// A value, or a text as written.
    Claim(ClaimText),
}

/// A row of a card whose texts the context resolves: a label and an optional value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SaidRow {
    /// The label.
    pub(crate) label: Said,
    /// The value; `None` for a full-text row.
    pub(crate) value: Option<Said>,
}

impl SaidRow {
    /// A row of the label alone.
    const fn full_text(label: Said) -> Self {
        Self { label, value: None }
    }
}

fn label_of(
    format: &impl ClaimsFormat,
    path: &[Concrete<'_>],
    described: &[ClaimEntry<'_>],
    display: Display<'_>,
) -> Result<Option<Said>, TextError> {
    let Some(found) = described.iter().find(|known| known.path.matches(path)) else {
        return Ok(None);
    };
    let entry = format_entry(&found.display, display.locales);
    entry
        .and_then(|entry| entry.get(format.label_key()))
        .and_then(Node::as_str)
        .map_or(Ok(None), Display::label)
}

/// A label as written, read through [`DisplayText`]; `None` for a text without a visible
/// character ([`DisplayText::visible`]), which the wallet's word or a member name then stands for.
pub(super) fn label_text(text: &str) -> Result<Option<String>, TextError> {
    match DisplayText::label(text) {
        Ok(label) => Ok(Some(label.into_string())),
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
/// for a claim when its path names no member or that name holds no visible character.
fn fallback_label(path: &[Concrete<'_>]) -> Result<Said, TextError> {
    let name = path.iter().rev().find_map(|step| match step {
        Concrete::Key(key) => Some(key),
        Concrete::Index(_) => None,
    });
    Ok(name
        .map_or(Ok(None), |name| label_text(name))?
        .map_or(Said::Wallet(WalletText::Claim), |label| {
            Said::Claim(ClaimText::Label { label })
        }))
}

/// An object is a heading row then its members; an array of values gives each element the
/// array's label; an array holding objects or arrays is a heading row then its elements. A claim
/// without a label in the metadata shows its last member name, or the wallet's word for a claim
/// when its path names no member. A scalar value shows by its type: a boolean as the wallet's yes
/// or no, `null` as the wallet's text for no value, a number as a count or an exact decimal and
/// beyond those as the JSON text the credential wrote, a byte string by its length, a date of the
/// view's `dates` by its literal, which the wallet's wording formats. The labels and names read
/// through [`DisplayText`]; the credential's other strings show as written.
///
/// # Errors
///
/// [`CardError`]: a label that breaks the rule of display text, or a claim's natural number that
/// is no count literal.
pub(super) fn value_rows(
    format: &impl ClaimsFormat,
    path: &[Concrete<'_>],
    value: &Node<'_>,
    described: &[ClaimEntry<'_>],
    display: Display<'_>,
    inherited: Option<&Said>,
) -> Result<Vec<SaidRow>, CardError> {
    let label = label_of(format, path, described, display)
        .map_err(CardError::Text)?
        .or_else(|| inherited.cloned());
    let child = |step: Concrete<'_>| -> Vec<Concrete<'_>> {
        path.iter()
            .map(Concrete::to_owned_step)
            .chain(std::iter::once(step.to_owned_step()))
            .collect()
    };
    let text = match value {
        Node::Object(object) => {
            let mut rows: Vec<SaidRow> = label.map(SaidRow::full_text).into_iter().collect();
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
                rows.extend(label.map(SaidRow::full_text));
                None
            } else if shown.is_empty() {
                label
            } else {
                Some(
                    label
                        .map_or_else(|| fallback_label(path), Ok)
                        .map_err(CardError::Text)?,
                )
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
        Node::Bool(true) => Said::Boolean(BooleanText::Yes),
        Node::Bool(false) => Said::Boolean(BooleanText::No),
        Node::Null => Said::Wallet(WalletText::Null),
        Node::Number(number) => Said::Claim(
            match number_value(number.text()).map_err(CardError::Count)? {
                Some(value) => ClaimText::Number { value },
                None => ClaimText::Text {
                    value: number.text().to_owned(),
                },
            },
        ),
        Node::String(written) => Said::Claim(
            match (
                entry_at(display.byte_strings, path),
                entry_at(display.dates, path),
            ) {
                (Some(length), _) => ClaimText::Bytes {
                    length: length.clone(),
                },
                (None, Some(date)) => date.clone(),
                (None, None) => ClaimText::Text {
                    value: written.to_string(),
                },
            },
        ),
    };
    Ok(vec![SaidRow {
        label: label
            .map_or_else(|| fallback_label(path), Ok)
            .map_err(CardError::Text)?,
        value: Some(text),
    }])
}

/// A JSON number (RFC 8259 §6) as an exact value: a natural number as a count, another as a
/// decimal; `None` past an `i32` exponent, a decimal's 38 fraction digits or an `i128`'s units,
/// the only failures the JSON grammar leaves the integer parses.
///
/// # Errors
///
/// [`Malformed`]: a natural number's digits are no count literal, which no JSON number writes.
fn number_value(text: &str) -> Result<Option<ExactNumber>, Malformed> {
    let Some(Exact {
        negative,
        digits,
        scale,
    }) = Exact::of(text)
    else {
        return Ok(None);
    };
    if !negative && scale == 0 {
        let natural = match digits.trim_start_matches('0') {
            "" => "0",
            natural => natural,
        };
        return Count::parse(natural).map(|count| Some(ExactNumber::Count(count)));
    }
    let Ok(units) = digits.parse::<i128>() else {
        return Ok(None);
    };
    Ok(Decimal::new(if negative { -units } else { units }, scale).map(ExactNumber::Decimal))
}

/// A JSON number's value as a sign, digits and a scale: `0.5e1` is `05` at scale 0, `0e5` is
/// `000000` at scale 0.
struct Exact {
    negative: bool,
    digits: String,
    scale: u8,
}

impl Exact {
    /// The value `text` writes; `None` past an `i32` exponent or 38 places of ten.
    fn of(text: &str) -> Option<Self> {
        let (mantissa, exponent) = match text.split_once(['e', 'E']) {
            Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().ok()?),
            None => (text, 0),
        };
        let (negative, unsigned) = match mantissa.strip_prefix('-') {
            Some(unsigned) => (true, unsigned),
            None => (false, mantissa),
        };
        let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
        let scale = i64::try_from(fraction.len())
            .ok()?
            .checked_sub(i64::from(exponent))?;
        let mut digits = format!("{whole}{fraction}");
        if scale < 0 {
            let zeros = usize::try_from(scale.unsigned_abs())
                .ok()
                .filter(|zeros| *zeros <= 38)?;
            digits.push_str(&"0".repeat(zeros));
        }
        Some(Self {
            negative,
            digits,
            scale: u8::try_from(scale.max(0)).ok()?,
        })
    }
}

impl Concrete<'_> {
    fn to_owned_step(&self) -> Concrete<'static> {
        match self {
            Concrete::Key(key) => Concrete::Key(std::borrow::Cow::Owned(key.to_string())),
            Concrete::Index(at) => Concrete::Index(*at),
        }
    }
}
