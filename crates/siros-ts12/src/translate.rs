//! The translation of a type's TS12 metadata into PaSO's model (section 4.10.2's display table):
//! claim paths without `payload`, `visualisation` level 4 internal except the fields a type always
//! shows, value types from TS12's field tables, `lang` read as PaSO's `locale` under TS12's own
//! meaning of its tags.
//!
//! A payload field without labels ceases unless level 4 hides it (TS12 §3.3.1: an unset level is 3,
//! level 3 displays, labels unavailable cease). WE BUILD's own metadata leaves `transaction_id`,
//! `date_time`, `payee.id` and `currency` without claim metadata (CS-12 §7.2, its test bed), which
//! therefore stay internal.

use std::borrow::Cow;

use siros_explain::Explain;
use siros_openid4vp::json::{JsonError, Node};
use siros_paso::metadata::UiKey;

use crate::document::{BuiltInEntry, Ts12Type};

/// Why a type is unsupported for a credential (TS12 §3.2 step 5, §3.3.1: cease).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "ts12.unsupported")]
pub enum Ts12Unsupported {
    /// No `ts12` document.
    #[error("the credential holds no TS12 metadata")]
    NoDocument,
    /// `category` absent or other than SCA's.
    #[error("the credential's category is no SCA attestation's")]
    Category,
    /// No configured attestation type among the credential's types.
    #[error("the credential's types name no configured attestation type")]
    AttestationType,
    /// The type no key of `transaction_data_types`.
    #[error("{kind} is no key of the credential's transaction_data_types")]
    NotListed {
        /// The entry's type.
        kind: String,
    },
    /// A schema naming no built-in type: an issuer's JSON Schema, or none.
    #[error("{schema}: the schema names no built-in type")]
    Schema {
        /// The schema as written; empty when absent.
        schema: String,
    },
    /// `affirmative_action_label` absent.
    #[error("affirmative_action_label is absent")]
    Affirmative,
    /// A field TS12 §3.3.1 displays without labels: one the type displays at every level, a claim
    /// without `display` below level 4, or a payload field the claims metadata omits.
    #[error("{field} has no labels")]
    Labels {
        /// The field.
        field: String,
    },
    /// Claim metadata or UI labels outside TS12's: a path outside the type's field table, a level
    /// outside 1 to 4, or a display entry without its `lang` and text as strings.
    #[error("{at}: metadata outside TS12's form")]
    Metadata {
        /// The claim's path as written, or the UI element.
        at: String,
    },
}

/// What the display rules ask of a leaf field.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shown {
    /// Displayed at every level, and its labels required.
    Always,
    /// Displayed under its claim metadata's level; internal when the claims metadata omits it.
    Declared,
    /// Displayed under its claim metadata's level; a payload holding it needs that metadata.
    WhenHeld,
}

/// A field of a type's table: its path below `payload`, its PaSO value type (`None` for plain
/// text), and for a leaf what the display rules ask of it.
struct Field {
    path: &'static [&'static str],
    value_type: Option<&'static str>,
    leaf: Option<Shown>,
}

impl Field {
    const fn leaf(path: &'static [&'static str], value_type: Option<&'static str>) -> Self {
        Self {
            path,
            value_type,
            leaf: Some(Shown::WhenHeld),
        }
    }

    const fn declared(path: &'static [&'static str], value_type: Option<&'static str>) -> Self {
        Self {
            path,
            value_type,
            leaf: Some(Shown::Declared),
        }
    }

    const fn always(path: &'static [&'static str], value_type: Option<&'static str>) -> Self {
        Self {
            path,
            value_type,
            leaf: Some(Shown::Always),
        }
    }

    const fn object(path: &'static [&'static str]) -> Self {
        Self {
            path,
            value_type: Some("label_only"),
            leaf: None,
        }
    }

    fn shown(&self, shown: Shown) -> bool {
        self.leaf == Some(shown)
    }
}

const AMOUNT: Option<&str> = Some("iso_currency_amount");
const BOOLEAN: Option<&str> = Some("boolean");
const DATE: Option<&str> = Some("iso_date");
const DATE_TIME: Option<&str> = Some("iso_date_time");

const PAYMENT_FIELDS: [Field; 30] = [
    Field::declared(&["transaction_id"], None),
    Field::declared(&["date_time"], DATE_TIME),
    Field::object(&["payee"]),
    Field::always(&["payee", "name"], None),
    Field::declared(&["payee", "id"], None),
    Field::leaf(&["payee", "logo"], Some("image")),
    Field::leaf(&["payee", "website"], Some("url")),
    Field::object(&["pisp"]),
    Field::leaf(&["pisp", "legal_name"], None),
    Field::leaf(&["pisp", "brand_name"], None),
    Field::leaf(&["pisp", "domain_name"], None),
    Field::leaf(&["execution_date"], DATE),
    Field::declared(&["currency"], Some("iso_currency")),
    Field::always(&["amount"], AMOUNT),
    Field::leaf(&["amount_estimated"], BOOLEAN),
    Field::leaf(&["amount_earmarked"], BOOLEAN),
    Field::leaf(&["sct_inst"], BOOLEAN),
    Field::object(&["recurrence"]),
    Field::leaf(&["recurrence", "start_date"], DATE),
    Field::leaf(&["recurrence", "end_date"], DATE),
    Field::leaf(&["recurrence", "number"], None),
    Field::leaf(&["recurrence", "frequency"], Some("frequency")),
    Field::object(&["recurrence", "mit_options"]),
    Field::leaf(&["recurrence", "mit_options", "amount_variable"], BOOLEAN),
    Field::leaf(&["recurrence", "mit_options", "min_amount"], AMOUNT),
    Field::leaf(&["recurrence", "mit_options", "max_amount"], AMOUNT),
    Field::leaf(&["recurrence", "mit_options", "total_amount"], AMOUNT),
    Field::leaf(&["recurrence", "mit_options", "initial_amount"], AMOUNT),
    Field::leaf(
        &["recurrence", "mit_options", "initial_amount_number"],
        None,
    ),
    Field::leaf(&["recurrence", "mit_options", "apr"], None),
];

const LOGIN_FIELDS: [Field; 4] = [
    Field::declared(&["transaction_id"], None),
    Field::declared(&["date_time"], DATE_TIME),
    Field::leaf(&["service"], None),
    Field::always(&["action"], None),
];

const fn fields(kind: Ts12Type) -> &'static [Field] {
    match kind {
        Ts12Type::Payment => &PAYMENT_FIELDS,
        Ts12Type::LoginRisk => &LOGIN_FIELDS,
    }
}

/// The level TS12 §3.3.1 hides.
const HIDDEN: u64 = 4;

/// The type's metadata in PaSO's form, in the claims metadata's order, each field it omits
/// appended internal.
///
/// # Errors
///
/// [`Ts12Unsupported`]: the rule of TS12 §3.3 the metadata leaves unmet.
pub fn paso_metadata(entry: &BuiltInEntry<'_>) -> Result<Node<'static>, Ts12Unsupported> {
    let catalogue = entry
        .ui_labels()
        .and_then(Node::as_object)
        .filter(|labels| labels.get("affirmative_action_label").is_some())
        .ok_or(Ts12Unsupported::Affirmative)?;
    let table = fields(entry.kind());
    let written = entry.claims().and_then(Node::as_array).unwrap_or(&[]);
    let mut seen: Vec<&'static Field> = Vec::new();
    let mut claims = Vec::with_capacity(table.len());
    for claim in written {
        let (field, translated) = translated_claim(claim, table)?;
        seen.push(field);
        claims.push(translated);
    }
    if let Some(unlabelled) = table
        .iter()
        .find(|field| field.shown(Shown::Always) && !labelled(field, written))
    {
        return Err(Ts12Unsupported::Labels {
            field: unlabelled.path.join("."),
        });
    }
    for field in table {
        if field.leaf.is_some() && !seen.iter().any(|known| known.path == field.path) {
            claims.push(internal(field.path).map_err(|_| metadata_at(field.path.join(".")))?);
        }
    }
    let labels = catalogue
        .members()
        .iter()
        .filter(|member| UiKey::of(&member.name).is_some())
        .map(|member| {
            let name: &str = &member.name;
            Ok((
                Cow::Owned(name.to_owned()),
                translated_array(&member.value, "value", "value", name)?,
            ))
        })
        .collect::<Result<Vec<_>, Ts12Unsupported>>()?;
    let ui = Node::object(labels).map_err(|_| metadata_at("ui_labels".to_owned()))?;
    Node::object([
        (Cow::Borrowed("claims"), Node::Array(claims)),
        (Cow::Borrowed("ui_labels"), ui),
    ])
    .map_err(|_| metadata_at("the metadata".to_owned()))
}

/// TS12 §3.3.1 over the payload: each field it holds that the claims metadata omits needs labels.
///
/// # Errors
///
/// [`Ts12Unsupported::Labels`]: the first such field in the type's table.
pub(crate) fn labels_for(
    entry: &BuiltInEntry<'_>,
    payload: &Node<'_>,
) -> Result<(), Ts12Unsupported> {
    let written = entry.claims().and_then(Node::as_array).unwrap_or(&[]);
    let omitted = fields(entry.kind()).iter().find(|field| {
        field.shown(Shown::WhenHeld)
            && field
                .path
                .iter()
                .try_fold(payload, |node, step| node.get(step))
                .is_some()
            && !written
                .iter()
                .any(|claim| field_path(claim).is_some_and(|path| path == field.path))
    });
    omitted.map_or(Ok(()), |field| {
        Err(Ts12Unsupported::Labels {
            field: field.path.join("."),
        })
    })
}

const fn metadata_at(at: String) -> Ts12Unsupported {
    Ts12Unsupported::Metadata { at }
}

/// Whether the claims metadata holds a `display` array for the field.
fn labelled(field: &Field, written: &[Node<'_>]) -> bool {
    written.iter().any(|claim| {
        field_path(claim).is_some_and(|path| path == field.path)
            && claim
                .get("display")
                .and_then(Node::as_array)
                .is_some_and(|display| !display.is_empty())
    })
}

/// A claim's path below `payload`; `None` for a path elsewhere or of another form.
fn field_path<'c>(claim: &'c Node<'_>) -> Option<Vec<&'c str>> {
    let path = claim.get("path")?.as_array()?;
    let (first, rest) = path.split_first()?;
    (first.as_str() == Some("payload"))
        .then(|| rest.iter().map(Node::as_str).collect())
        .flatten()
}

fn path_node(path: &[&str]) -> Node<'static> {
    Node::Array(
        path.iter()
            .map(|step| Node::String(Cow::Owned((*step).to_owned())))
            .collect(),
    )
}

fn internal(path: &[&str]) -> Result<Node<'static>, JsonError> {
    Node::object([(Cow::Borrowed("path"), path_node(path))])
}

fn translated_claim(
    claim: &Node<'_>,
    table: &'static [Field],
) -> Result<(&'static Field, Node<'static>), Ts12Unsupported> {
    let refused = || {
        metadata_at(
            claim
                .get("path")
                .map_or_else(String::new, |path| path.python_compact().to_string()),
        )
    };
    let path = field_path(claim).ok_or_else(refused)?;
    let field = table
        .iter()
        .find(|field| field.path == path.as_slice())
        .ok_or_else(refused)?;
    let level = match claim.get("visualisation") {
        None => None,
        Some(Node::Number(level)) => Some(
            level
                .as_u64()
                .filter(|level| (1..=HIDDEN).contains(level))
                .ok_or_else(refused)?,
        ),
        Some(_) => return Err(refused()),
    };
    let display = claim
        .get("display")
        .filter(|display| display.as_array().is_none_or(|labels| !labels.is_empty()));
    if display.is_none() && field.leaf.is_some() && level != Some(HIDDEN) {
        return Err(Ts12Unsupported::Labels {
            field: field.path.join("."),
        });
    }
    let display = display.filter(|_| level != Some(HIDDEN) || field.shown(Shown::Always));
    let mut out = vec![(Cow::Borrowed("path"), path_node(field.path))];
    if let Some(display) = display {
        let at = field.path.join(".");
        out.push((
            Cow::Borrowed("display"),
            translated_array(display, "label", "name", &at)?,
        ));
        if let Some(value_type) = field.value_type {
            out.push((
                Cow::Borrowed("value_type"),
                Node::String(Cow::Borrowed(value_type)),
            ));
        }
    }
    let translated = Node::object(out).map_err(|_| refused())?;
    Ok((field, translated))
}

/// A label array with `lang` read as `locale`, its tags as TS12 means them, and `text` read as
/// `paso`'s member; other members, `description` among them, unused.
fn translated_array(
    array: &Node<'_>,
    text: &str,
    paso: &'static str,
    at: &str,
) -> Result<Node<'static>, Ts12Unsupported> {
    let refused = || metadata_at(at.to_owned());
    let items = array.as_array().ok_or_else(refused)?;
    let tags = items
        .iter()
        .map(|item| item.get("lang").and_then(Node::as_str))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(refused)?;
    items
        .iter()
        .zip(generic_tags(&tags))
        .map(|(item, tag)| {
            let label = item.get(text).and_then(Node::as_str).ok_or_else(refused)?;
            Node::object([
                (Cow::Borrowed("locale"), Node::String(Cow::Owned(tag))),
                (
                    Cow::Borrowed(paso),
                    Node::String(Cow::Owned(label.to_owned())),
                ),
            ])
            .map_err(|_| refused())
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Node::Array)
}

/// Each tag as TS12 means it: a tag whose language's generic tag no entry holds takes that generic
/// tag, the first in order when several regions of one language stand alone. PaSO's Lookup then
/// reaches the entry from any list naming the language.
#[must_use]
pub fn generic_tags(tags: &[&str]) -> Vec<String> {
    let mut held: Vec<String> = tags.iter().map(|tag| tag.to_ascii_lowercase()).collect();
    tags.iter()
        .map(|tag| {
            let generic = generic_tag(tag);
            let lowered = generic.to_ascii_lowercase();
            if held.contains(&lowered) {
                (*tag).to_owned()
            } else {
                held.push(lowered);
                generic.to_owned()
            }
        })
        .collect()
}

/// The tag without its region and variants, its script kept (RFC 5646 §2.1): the language, its
/// extended language subtags and its script. A grandfathered or private-use tag stays whole.
fn generic_tag(tag: &str) -> &str {
    let mut subtags = tag.split('-');
    let Some(language) = subtags.next().filter(|language| language.len() >= 2) else {
        return tag;
    };
    let alphabetic = |subtag: &str| subtag.bytes().all(|byte| byte.is_ascii_alphabetic());
    let mut end = language.len();
    for subtag in subtags {
        if !alphabetic(subtag) || !matches!(subtag.len(), 3 | 4) {
            break;
        }
        end += 1 + subtag.len();
        if subtag.len() == 4 {
            break;
        }
    }
    tag.get(..end).unwrap_or(tag)
}
