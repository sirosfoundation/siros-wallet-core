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
use siros_openid4vp::json::Node;
use siros_openid4vp::known_object;
use siros_paso::metadata::UiKey;

use crate::document::{BuiltInEntry, Ts12Type};
use crate::field::{
    ACTION, AMOUNT, AMOUNT_EARMARKED, AMOUNT_ESTIMATED, AMOUNT_VARIABLE, APR, CURRENCY, DATE_TIME,
    END_DATE, EXECUTION_DATE, FREQUENCY, FieldPath, INITIAL_AMOUNT, INITIAL_AMOUNT_NUMBER,
    MAX_AMOUNT, MIN_AMOUNT, MIT_OPTIONS, NUMBER, PAYEE, PAYEE_ID, PAYEE_LOGO, PAYEE_NAME,
    PAYEE_WEBSITE, PISP, PISP_BRAND_NAME, PISP_DOMAIN_NAME, PISP_LEGAL_NAME, RECURRENCE, SCT_INST,
    SERVICE, START_DATE, TOTAL_AMOUNT, TRANSACTION_ID,
};

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

/// A PaSO value type of a leaf field; a field without one is plain text.
#[derive(Clone, Copy)]
enum ValueType {
    Amount,
    Boolean,
    Currency,
    Date,
    DateTime,
    Frequency,
    Image,
    Url,
}

impl ValueType {
    const fn wire(self) -> &'static str {
        match self {
            Self::Amount => "iso_currency_amount",
            Self::Boolean => "boolean",
            Self::Currency => "iso_currency",
            Self::Date => "iso_date",
            Self::DateTime => "iso_date_time",
            Self::Frequency => "frequency",
            Self::Image => "image",
            Self::Url => "url",
        }
    }
}

/// An object of a field table, shown by its label alone, or a leaf under the display rules.
#[derive(Clone, Copy)]
enum Role {
    Object,
    Leaf {
        value_type: Option<ValueType>,
        shown: Shown,
    },
}

/// A field of a type's table.
struct Field {
    path: FieldPath,
    role: Role,
}

impl Field {
    const fn leaf(path: FieldPath, value_type: Option<ValueType>) -> Self {
        Self::shown_as(path, value_type, Shown::WhenHeld)
    }

    const fn declared(path: FieldPath, value_type: Option<ValueType>) -> Self {
        Self::shown_as(path, value_type, Shown::Declared)
    }

    const fn always(path: FieldPath, value_type: Option<ValueType>) -> Self {
        Self::shown_as(path, value_type, Shown::Always)
    }

    const fn shown_as(path: FieldPath, value_type: Option<ValueType>, shown: Shown) -> Self {
        Self {
            path,
            role: Role::Leaf { value_type, shown },
        }
    }

    const fn object(path: FieldPath) -> Self {
        Self {
            path,
            role: Role::Object,
        }
    }

    const fn is_leaf(&self) -> bool {
        matches!(self.role, Role::Leaf { .. })
    }

    fn shown(&self, wanted: Shown) -> bool {
        matches!(self.role, Role::Leaf { shown, .. } if shown == wanted)
    }

    /// The value type PaSO's metadata states for the field.
    const fn value_type(&self) -> Option<&'static str> {
        match self.role {
            Role::Object => Some("label_only"),
            Role::Leaf {
                value_type: Some(value_type),
                ..
            } => Some(value_type.wire()),
            Role::Leaf {
                value_type: None, ..
            } => None,
        }
    }

    /// Whether a claim's path below `payload` is the field's.
    fn is_at(&self, path: &[&str]) -> bool {
        self.path.steps().eq(path.iter().copied())
    }
}

const AMOUNT_VALUE: Option<ValueType> = Some(ValueType::Amount);
const BOOLEAN: Option<ValueType> = Some(ValueType::Boolean);
const CALENDAR: Option<ValueType> = Some(ValueType::Date);
const TIMESTAMP: Option<ValueType> = Some(ValueType::DateTime);

const PAYMENT_FIELDS: [Field; 30] = [
    Field::declared(TRANSACTION_ID, None),
    Field::declared(DATE_TIME, TIMESTAMP),
    Field::object(PAYEE),
    Field::always(PAYEE_NAME, None),
    Field::declared(PAYEE_ID, None),
    Field::leaf(PAYEE_LOGO, Some(ValueType::Image)),
    Field::leaf(PAYEE_WEBSITE, Some(ValueType::Url)),
    Field::object(PISP),
    Field::leaf(PISP_LEGAL_NAME, None),
    Field::leaf(PISP_BRAND_NAME, None),
    Field::leaf(PISP_DOMAIN_NAME, None),
    Field::leaf(EXECUTION_DATE, CALENDAR),
    Field::declared(CURRENCY, Some(ValueType::Currency)),
    Field::always(AMOUNT, AMOUNT_VALUE),
    Field::leaf(AMOUNT_ESTIMATED, BOOLEAN),
    Field::leaf(AMOUNT_EARMARKED, BOOLEAN),
    Field::leaf(SCT_INST, BOOLEAN),
    Field::object(RECURRENCE),
    Field::leaf(START_DATE, CALENDAR),
    Field::leaf(END_DATE, CALENDAR),
    Field::leaf(NUMBER, None),
    Field::leaf(FREQUENCY, Some(ValueType::Frequency)),
    Field::object(MIT_OPTIONS),
    Field::leaf(AMOUNT_VARIABLE, BOOLEAN),
    Field::leaf(MIN_AMOUNT, AMOUNT_VALUE),
    Field::leaf(MAX_AMOUNT, AMOUNT_VALUE),
    Field::leaf(TOTAL_AMOUNT, AMOUNT_VALUE),
    Field::leaf(INITIAL_AMOUNT, AMOUNT_VALUE),
    Field::leaf(INITIAL_AMOUNT_NUMBER, None),
    Field::leaf(APR, None),
];

const LOGIN_FIELDS: [Field; 4] = [
    Field::declared(TRANSACTION_ID, None),
    Field::declared(DATE_TIME, TIMESTAMP),
    Field::leaf(SERVICE, None),
    Field::always(ACTION, None),
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
            field: unlabelled.path.as_str().to_owned(),
        });
    }
    for field in table {
        if field.is_leaf() && !seen.iter().any(|known| known.path == field.path) {
            claims.push(internal(field.path));
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
    Ok(Node::Object(known_object! {
        "claims" => Some(Node::Array(claims)),
        "ui_labels" => Some(ui),
    }))
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
                .steps()
                .try_fold(payload, |node, step| node.get(step))
                .is_some()
            && !written
                .iter()
                .any(|claim| field_path(claim).is_some_and(|path| field.is_at(&path)))
    });
    omitted.map_or(Ok(()), |field| {
        Err(Ts12Unsupported::Labels {
            field: field.path.as_str().to_owned(),
        })
    })
}

const fn metadata_at(at: String) -> Ts12Unsupported {
    Ts12Unsupported::Metadata { at }
}

/// Whether the claims metadata holds a `display` array for the field.
fn labelled(field: &Field, written: &[Node<'_>]) -> bool {
    written.iter().any(|claim| {
        field_path(claim).is_some_and(|path| field.is_at(&path))
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

fn path_node(path: FieldPath) -> Node<'static> {
    Node::Array(
        path.steps()
            .map(|step| Node::String(Cow::Borrowed(step)))
            .collect(),
    )
}

fn internal(path: FieldPath) -> Node<'static> {
    Node::Object(known_object! { "path" => Some(path_node(path)) })
}

fn translated_claim(
    claim: &Node<'_>,
    table: &'static [Field],
) -> Result<(&'static Field, Node<'static>), Ts12Unsupported> {
    let refused = || {
        metadata_at(
            claim
                .get("path")
                .map_or_else(String::new, |path| path.json_compact().to_string()),
        )
    };
    let path = field_path(claim).ok_or_else(refused)?;
    let field = table
        .iter()
        .find(|field| field.is_at(&path))
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
    if display.is_none() && field.is_leaf() && level != Some(HIDDEN) {
        return Err(Ts12Unsupported::Labels {
            field: field.path.as_str().to_owned(),
        });
    }
    let display = display.filter(|_| level != Some(HIDDEN) || field.shown(Shown::Always));
    let mut out = vec![(Cow::Borrowed("path"), path_node(field.path))];
    if let Some(display) = display {
        out.push((
            Cow::Borrowed("display"),
            translated_array(display, "label", "name", field.path.as_str())?,
        ));
        if let Some(value_type) = field.value_type() {
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
