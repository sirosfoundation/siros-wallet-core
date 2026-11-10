//! View §3 `template:`: placeholders `{n}` naming the claim at index `n` of the metadata's
//! `claims`, each `null` of the referenced path resolved to the referencing instance's index. A
//! template label names each referenced value as an argument of its converted message
//! ([`crate::view`]). A template value of an inner text kind joins its text and each referenced
//! value of a typed kind, shown as its statement shows it alone (step 3); an inner kind that
//! parses its text reads the interpolation as written, as its value type takes precedence over
//! theirs.

use crate::markdown::spans;
use crate::value::{BadValue, Breach, FormattedKind, Parsed, ValueKind, Written, formatted};
use siros_openid4vp::claims::Step;
use siros_openid4vp::json::Node;
use siros_openid4vp::text::DisplayText;

use crate::conform::{ClaimIndex, NullIndices, written};
use crate::metadata::{ClaimMeta, RESERVED, ValueType, kind_name};
use crate::outcome::NotCompatible;
use crate::path::{at, substitute};

/// A piece of a template: text as written, or a placeholder `\{[0-9]+\}`. A template's pieces,
/// in order, write it exactly.
#[derive(Debug, Clone, Copy)]
enum Piece<'t> {
    Text(&'t str),
    Placeholder(Placeholder<'t>),
}

/// A placeholder in a template: its decimal digits.
#[derive(Debug, Clone, Copy)]
struct Placeholder<'t> {
    digits: &'t str,
}

impl Placeholder<'_> {
    /// The claim index the placeholder names, `None` beyond the platform's integers.
    fn index(&self) -> Option<usize> {
        self.digits.parse().ok()
    }

    /// Appends the placeholder as written.
    fn write(&self, out: &mut String) {
        out.push('{');
        out.push_str(self.digits);
        out.push('}');
    }
}

/// The pieces of a template, in order.
fn pieces(template: &str) -> Vec<Piece<'_>> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some((text, after)) = rest.split_once('{') {
        out.push(Piece::Text(text));
        let closed = after
            .trim_start_matches(|c: char| c.is_ascii_digit())
            .starts_with('}');
        match after.split_once(|c: char| !c.is_ascii_digit()) {
            Some((digits, tail)) if closed && !digits.is_empty() => {
                out.push(Piece::Placeholder(Placeholder { digits }));
                rest = tail;
            }
            _ => {
                out.push(Piece::Text("{"));
                rest = after;
            }
        }
    }
    out.push(Piece::Text(rest));
    out
}

/// The placeholders of a template, leftmost first.
fn placeholders(template: &str) -> impl Iterator<Item = Placeholder<'_>> {
    pieces(template)
        .into_iter()
        .filter_map(|piece| match piece {
            Piece::Placeholder(placeholder) => Some(placeholder),
            Piece::Text(_) => None,
        })
}

/// A template with each placeholder that names a claim replaced by [`RESERVED`], which a
/// template label does not hold, and the claims those placeholders name, in order. Other
/// placeholders stay literal.
pub(crate) fn marked(template: &str, claims: &[ClaimMeta<'_>]) -> (String, Vec<ClaimIndex>) {
    let mut marked = String::with_capacity(template.len());
    let mut named = Vec::new();
    for piece in pieces(template) {
        match piece {
            Piece::Text(text) => marked.push_str(text),
            Piece::Placeholder(placeholder) => {
                match placeholder.index().filter(|index| *index < claims.len()) {
                    Some(index) => {
                        marked.push(RESERVED);
                        named.push(ClaimIndex(index));
                    }
                    None => placeholder.write(&mut marked),
                }
            }
        }
    }
    (marked, named)
}

/// A placeholder's referenced claim, when its index names one: the referenced value is read
/// with the referencing instance's `null` indices.
struct Reference<'c, 'm> {
    index: ClaimIndex,
    claim: &'c ClaimMeta<'m>,
}

impl<'c, 'm> Reference<'c, 'm> {
    fn of(placeholder: &Placeholder<'_>, claims: &'c [ClaimMeta<'m>]) -> Option<Self> {
        let index = placeholder.index()?;
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
        for piece in pieces(self.0) {
            let placeholder = match piece {
                Piece::Text(text) => {
                    out.push_str(text);
                    continue;
                }
                Piece::Placeholder(placeholder) => placeholder,
            };
            let Some(reference) = Reference::of(&placeholder, claims) else {
                placeholder.write(&mut out);
                continue;
            };
            let value = reference
                .read(payload, nulls)?
                .ok_or(NotCompatible::TemplatesExhausted)?;
            out.push_str(&checked(reference.value_type(), value)?);
        }
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
        for piece in pieces(self.0) {
            let placeholder = match piece {
                Piece::Text(text) => {
                    parts.push(Part::Written(text.to_owned()));
                    continue;
                }
                Piece::Placeholder(placeholder) => placeholder,
            };
            let Some(reference) = Reference::of(&placeholder, claims) else {
                let mut literal = String::new();
                placeholder.write(&mut literal);
                parts.push(Part::Written(literal));
                continue;
            };
            let value = reference
                .read(payload, nulls)?
                .ok_or(NotCompatible::TemplatesExhausted)?;
            parts.push(match (text(reference.value_type(), value)?, kind) {
                (Parsed::Text(_), FormattedKind::MiniMarkdown) => {
                    Part::Written(value_written(value))
                }
                (Parsed::Text(shown), _) => Part::Written(shown),
                (typed, _) => Part::Typed(typed),
            });
        }
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
