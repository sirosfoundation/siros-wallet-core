//! View §3 `template:`: placeholders `{n}` naming the claim at index `n` of the metadata's
//! `claims`, each `null` of the referenced path resolved to the referencing instance's index. A
//! template label names each referenced value as an argument of its converted message
//! ([`crate::view`]). A template value of an inner text kind sets each referenced value of a
//! typed kind in the template as its typed text (step 3); an inner kind that parses its text
//! reads the interpolation as written, as its value type takes precedence over theirs.

use std::borrow::Cow;
use std::ops::Range;

use crate::markdown::spans;
use crate::value::{BadValue, Breach, FormattedKind, ValueKind, Written, formatted};
use siros_explain::{AllOf, Entry, RequestText, Text};
use siros_openid4vp::claims::Step;
use siros_openid4vp::json::Node;

use crate::conform::written;
use crate::metadata::{ClaimMeta, ValueType, kind_name};
use crate::outcome::NotCompatible;
use crate::path::{at, substitute};
use crate::view::argument;

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

/// A placeholder's referenced claim, when its index names one: the referenced value is read
/// with the referencing instance's `null` indices.
struct Reference<'c, 'm> {
    index: usize,
    claim: &'c ClaimMeta<'m>,
}

impl<'c, 'm> Reference<'c, 'm> {
    fn of(placeholder: &Placeholder, claims: &'c [ClaimMeta<'m>]) -> Option<Self> {
        let index = placeholder.index?;
        claims.get(index).map(|claim| Self { index, claim })
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
        nulls: &[usize],
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
            return Err(NotCompatible::MoreNulls(self.index));
        }
        let Some(path) = substitute(steps, nulls) else {
            return Ok(None);
        };
        let Some(value) = at(payload, &path)? else {
            return Ok(None);
        };
        if value_type == ValueType::Plain && value.as_str().is_none() {
            return Err(NotCompatible::ReferenceNotString(self.index));
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
        nulls: &[usize],
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
        nulls: &[usize],
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
    /// its styles, read after the values written as text are set in it) with each value of a
    /// typed kind as its typed text; of another kind, the interpolation read by the kind.
    pub(crate) fn value(
        &self,
        kind: FormattedKind,
        claims: &[ClaimMeta<'_>],
        payload: &Node<'_>,
        nulls: &[usize],
    ) -> Result<RequestText, NotCompatible> {
        let interpolated = self.interpolate(claims, payload, nulls)?;
        let (_, read) =
            formatted(kind, Written::Text(&interpolated)).map_err(|bad| NotCompatible::Value {
                value_type: kind_name(ValueKind::Formatted(kind)),
                bad,
            })?;
        if !matches!(kind, FormattedKind::Text | FormattedKind::MiniMarkdown) {
            return Ok(read);
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
            let typed = text(reference.value_type(), value)?;
            parts.push(match (typed.text(), kind) {
                (Text::Value(_) | Text::Query(_), _) => Part::Typed(typed),
                (_, FormattedKind::MiniMarkdown) => Part::Written(value_written(value)),
                (Text::Raw(shown), _) => Part::Written(shown.clone()),
                _ => Part::Typed(typed),
            });
            copied = placeholder.span.end;
        }
        parts.push(Part::Written(
            self.0.get(copied..).unwrap_or_default().to_owned(),
        ));
        if parts.iter().all(|part| matches!(part, Part::Written(_))) {
            return Ok(read);
        }
        let slot = slot(&parts).ok_or_else(|| NotCompatible::Value {
            value_type: kind_name(ValueKind::Formatted(kind)),
            bad: BadValue {
                kind: kind.as_str(),
                written: Written::Text(self.0).to_string(),
                why: Breach::NoSlot,
            },
        })?;
        let mut marked = String::new();
        let mut typed = Vec::new();
        for part in parts {
            match part {
                Part::Written(text) => marked.push_str(&text),
                Part::Typed(text) => {
                    marked.push(slot);
                    typed.push(text);
                }
            }
        }
        let plain = if kind == FormattedKind::MiniMarkdown {
            spans(&marked).into_iter().map(|span| span.text).collect()
        } else {
            marked
        };
        let mut typed = typed.into_iter();
        let mut items = Vec::new();
        for (k, piece) in plain.split(slot).enumerate() {
            if k > 0
                && let Some(text) = typed.next()
            {
                items.push(text);
            }
            if !piece.is_empty() {
                items.push(RequestText::raw(piece.to_owned()));
            }
        }
        Ok(AllOf::new(items).map_or(read, RequestText::joined))
    }

    /// Each referenced value as its message's argument, under its claim's name, by its value
    /// type, absent when the payload lacks it.
    pub(crate) fn arguments(
        &self,
        claims: &[ClaimMeta<'_>],
        payload: &Node<'_>,
        nulls: &[usize],
    ) -> Result<Vec<Entry<Cow<'static, str>, RequestText>>, NotCompatible> {
        let mut args: Vec<Entry<Cow<'static, str>, RequestText>> = Vec::new();
        for placeholder in placeholders(self.0) {
            let Some(reference) = Reference::of(&placeholder, claims) else {
                continue;
            };
            let value = match reference.read(payload, nulls)? {
                Some(value) => text(reference.value_type(), value)?,
                None => RequestText::absent(),
            };
            args.push(Entry::new(argument(reference.index), value));
        }
        Ok(args)
    }
}

/// A part of a template value: text shown as written, or a value's typed text.
enum Part {
    Written(String),
    Typed(RequestText),
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

/// A referenced value's text by its value type: a string as written without one.
fn text(value_type: ValueType, value: &Node<'_>) -> Result<RequestText, NotCompatible> {
    let kind = match value_type {
        ValueType::Kind(ValueKind::Formatted(kind)) => kind,
        _ => FormattedKind::Text,
    };
    formatted(kind, written(value))
        .map(|(_, text)| text)
        .map_err(|bad| NotCompatible::Value {
            value_type: kind_name(ValueKind::Formatted(kind)),
            bad,
        })
}

/// A referenced value as written, once it conforms to its value type.
fn checked(value_type: ValueType, value: &Node<'_>) -> Result<String, NotCompatible> {
    text(value_type, value).map(|_| value_written(value))
}
