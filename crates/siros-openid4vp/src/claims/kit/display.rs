//! A credential's card from its display metadata: the display entry for the wallet's locales and
//! the rows of its claims.

use super::super::{ClaimPath, Concrete};
use super::{ClaimsFormat, text_of};
use crate::ids::LocaleTag;
use crate::json::Node;
use crate::rows::{Label, Parsed, Row, Value};
use crate::text::atoms::python_space;
use crate::text::lookup;

/// A display array's entry for the wallet's locales, which SD-JWT VC §7 and §8.2 and
/// OpenID4VCI leave to the wallet ("most appropriate"): RFC 4647 Lookup over the priority list,
/// then basic filtering (a tag under the range), then the entry without a locale, then the
/// first entry.
#[must_use]
pub fn format_entry<'n, 'e>(
    entries: &'n [Node<'e>],
    locales: &[&LocaleTag<'_>],
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
    let looked_up = locales.iter().find_map(|locale| {
        lookup(locale, &tags).and_then(|tag| {
            tagged
                .iter()
                .find(|(t, _)| t == tag)
                .map(|(_, entry)| *entry)
        })
    });
    let filtered = || {
        locales.iter().find_map(|locale| {
            let range = format!("{}-", locale.as_str().to_lowercase());
            tagged
                .iter()
                .find(|(tag, _)| tag.to_lowercase().starts_with(&range))
                .map(|(_, entry)| *entry)
        })
    };
    let untagged = || entries.iter().find(|entry| entry.get("locale").is_none());
    looked_up
        .or_else(filtered)
        .or_else(untagged)
        .or_else(|| entries.first())
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
    locales: &[&LocaleTag<'_>],
) -> Option<String> {
    let (_, claim) = described
        .iter()
        .find(|(pointer, _)| pointer.matches(path))?;
    let entry = format_entry(
        claim.get("display").and_then(Node::as_array).unwrap_or(&[]),
        locales,
    )?;
    entry
        .get(format.label_key())
        .and_then(Node::as_str)
        .filter(|name| !name.trim_matches(python_space).is_empty())
        .map(str::to_owned)
}

/// An object is a heading row then its members; an array of values gives each element the
/// array's label; an array holding objects or arrays is a heading row then its elements. A claim
/// without a label in the metadata shows its last member name; a non-string value its JSON text.
pub(super) fn value_rows(
    format: &impl ClaimsFormat,
    path: &[Concrete<'_>],
    value: &Node<'_>,
    described: &[(ClaimPath<'_>, &Node<'_>)],
    locales: &[&LocaleTag<'_>],
    inherited: Option<&str>,
) -> Vec<Row> {
    let label = label_of(format, path, described, locales)
        .or_else(|| inherited.map(str::to_owned))
        .filter(|l| !l.is_empty());
    let fallback = path
        .iter()
        .rev()
        .find_map(|step| match step {
            Concrete::Key(key) => Some(key.to_string()),
            Concrete::Index(_) => None,
        })
        .unwrap_or_else(|| "claim".to_owned());
    let child = |step: Concrete<'_>| -> Vec<Concrete<'_>> {
        path.iter()
            .map(Concrete::to_owned_step)
            .chain(std::iter::once(step.to_owned_step()))
            .collect()
    };
    match value {
        Node::Object(object) => label
            .map(|label| Row::full_text(Label::text(label)))
            .into_iter()
            .chain(object.members().iter().flat_map(|member| {
                value_rows(
                    format,
                    &child(Concrete::Key(member.name.clone())),
                    &member.value,
                    described,
                    locales,
                    None,
                )
            }))
            .collect(),
        Node::Array(items) => {
            let nested = items
                .iter()
                .any(|item| matches!(item, Node::Object(_) | Node::Array(_)));
            let head = label
                .clone()
                .filter(|_| nested)
                .map(|label| Row::full_text(Label::text(label)));
            let passed = (!nested).then(|| label.unwrap_or_else(|| fallback.clone()));
            head.into_iter()
                .chain(items.iter().enumerate().flat_map(|(at, item)| {
                    value_rows(
                        format,
                        &child(Concrete::Index(at)),
                        item,
                        described,
                        locales,
                        passed.as_deref(),
                    )
                }))
                .collect()
        }
        scalar => vec![Row::new(
            Label::text(label.unwrap_or(fallback)),
            Value::Formatted {
                parsed: Parsed::Text,
                text: text_of(scalar),
            },
        )],
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
