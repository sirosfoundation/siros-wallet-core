//! View §3 `template:`: placeholders `{n}` naming the claim at index `n` of the metadata's
//! `claims`, each `null` of the referenced path resolved to the referencing instance's index. A
//! template label names each referenced value as an argument of its converted message
//! ([`crate::view`]). A template value of an inner text kind joins its text and each referenced
//! value of a typed kind, shown as its statement shows it alone (step 3); an inner kind that
//! parses its text reads the interpolation as written, as its value type takes precedence over
//! theirs.

use std::ops::Range;

use crate::markdown::spans;
use crate::value::{BadValue, Breach, FormattedKind, Parsed, ValueKind, Written, formatted};
use siros_openid4vp::claims::Step;
use siros_openid4vp::json::Node;
use siros_openid4vp::text::DisplayText;

use crate::conform::{ClaimIndex, NullIndices, written};
use crate::metadata::{ClaimMeta, RESERVED, ValueType, kind_name};
use crate::outcome::NotCompatible;
use crate::path::{at, substitute};

/// A placeholder in a template: its place and the claim index it names, `None` beyond the
/// platform's integers.
pub(crate) struct Placeholder {
    pub(crate) span: Range<usize>,
    pub(crate) index: Option<usize>,
}

/// The placeholders `\{[0-9]+\}` of a template, leftmost first, none overlapping.
pub(crate) fn placeholders(template: &str) -> Vec<Placeholder> {
    let bytes = template.as_bytes();
    let mut out = Vec::new();
    let mut k = 0;
    while let Some(offset) = bytes
        .get(k..)
        .and_then(|rest| rest.iter().position(|b| *b == b'{'))
    {
        let open = k + offset;
        let digits = bytes.get(open + 1..).map_or(0, |rest| {
            rest.iter().take_while(|b| b.is_ascii_digit()).count()
        });
        let close = open + 1 + digits;
        if digits > 0 && bytes.get(close) == Some(&b'}') {
            let index = template
                .get(open + 1..close)
                .and_then(|text| text.parse().ok());
            out.push(Placeholder {
                span: open..close + 1,
                index,
            });
            k = close + 1;
        } else {
            k = open + 1;
        }
    }
    out
}

/// A template with each placeholder that names a claim replaced by [`RESERVED`], which a
/// template label does not hold, and the claims those placeholders name, in order. Other
/// placeholders stay literal.
pub(crate) fn marked(template: &str, claims: &[ClaimMeta<'_>]) -> (String, Vec<ClaimIndex>) {
    let mut marked = String::with_capacity(template.len());
    let mut named = Vec::new();
    let mut copied = 0;
    for placeholder in placeholders(template) {
        let Some(index) = placeholder.index.filter(|index| *index < claims.len()) else {
            continue;
        };
        marked.push_str(
            template
                .get(copied..placeholder.span.start)
                .unwrap_or_default(),
        );
        marked.push(RESERVED);
        named.push(ClaimIndex(index));
        copied = placeholder.span.end;
    }
    marked.push_str(template.get(copied..).unwrap_or_default());
    (marked, named)
}

/// A placeholder's referenced claim, when its index names one: the referenced value is read
/// with the referencing instance's `null` indices.
struct Reference<'c, 'm> {
    index: ClaimIndex,
    claim: &'c ClaimMeta<'m>,
}

impl<'c, 'm> Reference<'c, 'm> {
    fn of(placeholder: &Placeholder, claims: &'c [ClaimMeta<'m>]) -> Option<Self> {
        let index = placeholder.index?;
        claims.get(index).map(|claim| Self {
            index: ClaimIndex(index),
            claim,
        })
    }

    /// The referenced claim's value type: a claim without `display` has none.
    fn value_type(&self) -> ValueType {
        self.claim
            .display
            .as_ref()
            .map_or(ValueType::Plain, |display| display.value)
    }

    /// The referenced value, `None` when the payload lacks it; refused for a reference View §3
    /// forbids.
    fn read<'n>(
        &self,
        payload: &'n Node<'n>,
        nulls: &NullIndices,
    ) -> Result<Option<&'n Node<'n>>, NotCompatible> {
        let value_type = self.value_type();
        let forbidden = match value_type {
            ValueType::Kind(ValueKind::Image) => Some("image".to_owned()),
            ValueType::LabelOnly => Some("label_only".to_owned()),
            ValueType::Template(inner) => Some(format!(
                "template:{}",
                kind_name(ValueKind::Formatted(inner))
            )),
            ValueType::Plain | ValueType::Kind(ValueKind::Formatted(_)) => None,
        };
        if let Some(value_type) = forbidden {
            return Err(NotCompatible::ForbiddenReference {
                placeholder: self.index,
                value_type,
            });
        }
        let steps = self.claim.path.steps();
        if steps.iter().filter(|step| **step == Step::All).count() > nulls.len() {
            return Err(NotCompatible::MoreNulls {
                placeholder: self.index,
            });
        }
        let Some(path) = substitute(steps, nulls) else {
            return Ok(None);
        };
        let Some(value) = at(payload, &path)? else {
            return Ok(None);
        };
        if value_type == ValueType::Plain && value.as_str().is_none() {
            return Err(NotCompatible::ReferenceNotString {
                placeholder: self.index,
            });
        }
        Ok(Some(value))
    }
}

/// A template: a `template:` label's or value's text.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Template<'t>(pub(crate) &'t str);

impl Template<'_> {
    /// Whether every placeholder naming a claim resolves for the referencing instance's `null`
    /// indices; refused for a reference View §3 forbids.
    pub(crate) fn complete(
        &self,
        claims: &[ClaimMeta<'_>],
        payload: &Node<'_>,
        nulls: &NullIndices,
    ) -> Result<bool, NotCompatible> {
        for placeholder in placeholders(self.0) {
            if let Some(reference) = Reference::of(&placeholder, claims)
                && reference.read(payload, nulls)?.is_none()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The template with each placeholder naming a claim replaced by the referenced value as
    /// written, each checked against its value type; other placeholders and inserted text stay
    /// literal. The template is complete for these indices; an absent reference makes it not
    /// compatible.
    pub(crate) fn interpolate(
        &self,
        claims: &[ClaimMeta<'_>],
        payload: &Node<'_>,
        nulls: &NullIndices,
    ) -> Result<String, NotCompatible> {
        let mut out = String::with_capacity(self.0.len());
        let mut copied = 0;
        for placeholder in placeholders(self.0) {
            let Some(reference) = Reference::of(&placeholder, claims) else {
                continue;
            };
            let value = reference
                .read(payload, nulls)?
                .ok_or(NotCompatible::TemplatesExhausted)?;
            out.push_str(
                self.0
                    .get(copied..placeholder.span.start)
                    .unwrap_or_default(),
            );
            out.push_str(&checked(reference.value_type(), value)?);
            copied = placeholder.span.end;
        }
        out.push_str(self.0.get(copied..).unwrap_or_default());
        Ok(out)
    }

    /// A template value of the inner kind `kind`, its interpolation as written held to `kind`
    /// first. Of `text` and `mini_markdown`, the template's text (a `mini_markdown` one without
    /// its styles, read after the values written as text are set in it) joined with each value
    /// of a typed kind; of another kind, the interpolation read by the kind.
    pub(crate) fn value(
        &self,
        kind: FormattedKind,
        claims: &[ClaimMeta<'_>],
        payload: &Node<'_>,
        nulls: &NullIndices,
    ) -> Result<Valued, NotCompatible> {
        let interpolated = self.interpolate(claims, payload, nulls)?;
        let read =
            formatted(kind, Written::Text(&interpolated)).map_err(|bad| NotCompatible::Value {
                value_type: kind_name(ValueKind::Formatted(kind)),
                bad,
            })?;
        if !matches!(kind, FormattedKind::Text | FormattedKind::MiniMarkdown) {
            return Ok(Valued::Alone(read));
        }
        let mut parts: Vec<Part> = Vec::new();
        let mut copied = 0;
        for placeholder in placeholders(self.0) {
            let Some(reference) = Reference::of(&placeholder, claims) else {
                continue;
            };
            let value = reference
                .read(payload, nulls)?
                .ok_or(NotCompatible::TemplatesExhausted)?;
            parts.push(Part::Written(
                self.0
                    .get(copied..placeholder.span.start)
                    .unwrap_or_default()
                    .to_owned(),
            ));
            parts.push(match (text(reference.value_type(), value)?, kind) {
                (Parsed::Text(_), FormattedKind::MiniMarkdown) => {
                    Part::Written(value_written(value))
                }
                (Parsed::Text(shown), _) => Part::Written(shown),
                (typed, _) => Part::Typed(typed),
            });
            copied = placeholder.span.end;
        }
        parts.push(Part::Written(
            self.0.get(copied..).unwrap_or_default().to_owned(),
        ));
        if parts.iter().all(|part| matches!(part, Part::Written(_))) {
            return Ok(Valued::Alone(read));
        }
        let slot = slot(&parts).ok_or_else(|| NotCompatible::Value {
            value_type: kind_name(ValueKind::Formatted(kind)),
            bad: BadValue {
                kind,
                written: Written::Text(self.0).named(),
                why: Breach::NoSlot,
            },
        })?;
        let mut marked = String::new();
        let mut typed = Vec::new();
        for part in parts {
            match part {
                Part::Written(text) => marked.push_str(&text),
                Part::Typed(value) => {
                    marked.push(slot);
                    typed.push(value);
                }
            }
        }
        Ok(Valued::Joined(Joined {
            marked,
            slot,
            typed,
            markdown: kind == FormattedKind::MiniMarkdown,
        }))
    }

    /// Whether the label this template writes for these indices shows a visible character
    /// ([`DisplayText::visible`]): one of its own text outside the markup, one of a referenced
    /// value shown as text, or a typed value, which the wallet's wording shows. Each referenced
    /// value shows as its argument of the converted message ([`crate::view`]), its markup as
    /// written.
    pub(crate) fn shows_visible(
        &self,
        claims: &[ClaimMeta<'_>],
        payload: &Node<'_>,
        nulls: &NullIndices,
    ) -> Result<bool, NotCompatible> {
        let (marked, _) = marked(self.0, claims);
        let own = spans(&marked)
            .iter()
            .flat_map(|span| span.text.chars())
            .any(|c| c != RESERVED && DisplayText::visible(c));
        if own {
            return Ok(true);
        }
        Ok(self
            .arguments(claims, payload, nulls)?
            .iter()
            .any(|(_, value)| match value {
                Parsed::Text(text) => text.chars().any(DisplayText::visible),
                Parsed::Boolean(_)
                | Parsed::Frequency(_)
                | Parsed::Date(_)
                | Parsed::Time(_)
                | Parsed::DateTime(_)
                | Parsed::Currency(_)
                | Parsed::Amount(_) => true,
            }))
    }

    /// Each referenced value the payload holds, under its claim, read by the claim's value type.
    pub(crate) fn arguments(
        &self,
        claims: &[ClaimMeta<'_>],
        payload: &Node<'_>,
        nulls: &NullIndices,
    ) -> Result<Vec<(ClaimIndex, Parsed)>, NotCompatible> {
        let mut args = Vec::new();
        for placeholder in placeholders(self.0) {
            let Some(reference) = Reference::of(&placeholder, claims) else {
                continue;
            };
            if let Some(value) = reference.read(payload, nulls)? {
                args.push((reference.index, text(reference.value_type(), value)?));
            }
        }
        Ok(args)
    }
}

/// A template value: one value shown alone, or text joined with typed values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Valued {
    /// The interpolation read by the inner kind, or a text without a typed value.
    Alone(Parsed),
    /// Text and typed values.
    Joined(Joined),
}

/// A template value's text with each typed value standing as `slot`, in order; a
/// `mini_markdown` value's styles are stripped when it is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Joined {
    marked: String,
    slot: char,
    typed: Vec<Parsed>,
    markdown: bool,
}

impl Joined {
    /// The value's text: its pieces, without their styles for `mini_markdown`, around each typed
    /// value as `show` writes it; `None` when reading the styles kept other than one slot per
    /// typed value.
    pub(crate) fn text<E>(
        self,
        mut show: impl FnMut(Parsed) -> Result<String, E>,
    ) -> Result<Option<String>, E> {
        let plain: String = if self.markdown {
            spans(&self.marked)
                .into_iter()
                .map(|span| span.text)
                .collect()
        } else {
            self.marked
        };
        let pieces: Vec<&str> = plain.split(self.slot).collect();
        let Some((first, rest)) = pieces.split_first() else {
            return Ok(None);
        };
        if rest.len() != self.typed.len() {
            return Ok(None);
        }
        let mut out = (*first).to_owned();
        for (piece, value) in rest.iter().zip(self.typed) {
            out.push_str(&show(value)?);
            out.push_str(piece);
        }
        Ok(Some(out))
    }
}

/// A part of a template value: text shown as written, or a typed value.
enum Part {
    Written(String),
    Typed(Parsed),
}

/// A character of Unicode's Supplementary Private Use Area-A that no written part holds: where
/// a typed value stands while a `mini_markdown` value is read; `None` when the parts hold all
/// 65,534.
fn slot(parts: &[Part]) -> Option<char> {
    ('\u{F0000}'..='\u{FFFFD}').find(|c| {
        !parts
            .iter()
            .any(|part| matches!(part, Part::Written(text) if text.contains(*c)))
    })
}

/// A referenced value as written: a string's text, any other JSON value's compact text.
fn value_written(value: &Node<'_>) -> String {
    value.written_compact()
}

/// A referenced value read by its value type: a string as written without one.
fn text(value_type: ValueType, value: &Node<'_>) -> Result<Parsed, NotCompatible> {
    let kind = match value_type {
        ValueType::Kind(ValueKind::Formatted(kind)) => kind,
        _ => FormattedKind::Text,
    };
    formatted(kind, written(value)).map_err(|bad| NotCompatible::Value {
        value_type: kind_name(ValueKind::Formatted(kind)),
        bad,
    })
}

/// A referenced value as written, once it conforms to its value type.
fn checked(value_type: ValueType, value: &Node<'_>) -> Result<String, NotCompatible> {
    text(value_type, value).map(|_| value_written(value))
}
