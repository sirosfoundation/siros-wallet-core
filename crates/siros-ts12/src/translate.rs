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
use siros_openid4vp::ids::TransactionType;
use siros_openid4vp::json::{Node, Object};
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
pub enum Ts12Unsupported {
    /// No `ts12` document.
    #[error("the credential holds no TS12 metadata")]
    #[explain(id = "unsupported.no_document")]
    NoDocument,
    /// `category` absent or other than SCA's.
    #[error("the credential's category is no SCA attestation's")]
    #[explain(id = "unsupported.category")]
    Category,
    /// No configured attestation type among the credential's types.
    #[error("the credential's types name no configured attestation type")]
    #[explain(id = "unsupported.attestation_type")]
    AttestationType,
    /// The type no key of `transaction_data_types`.
    #[error("{kind} is no key of the credential's transaction_data_types")]
    #[explain(id = "unsupported.not_listed")]
    NotListed {
        /// The entry's type.
        kind: TransactionType<'static>,
    },
    /// An entry with neither `schema` nor `schema_uri`.
    #[error("the type's entry names no schema")]
    #[explain(id = "unsupported.no_schema")]
    NoSchema,
    /// A `schema` or `schema_uri` that is no string (TS12 §4.1).
    #[error("the type's schema is no string")]
    #[explain(id = "unsupported.schema_form")]
    SchemaForm,
    /// A schema naming no built-in type: an issuer's JSON Schema.
    #[error("{schema}: the schema names no built-in type")]
    #[explain(id = "unsupported.schema")]
    Schema {
        /// The schema as written.
        schema: String,
    },
    /// `affirmative_action_label` absent.
    #[error("affirmative_action_label is absent")]
    #[explain(id = "unsupported.affirmative")]
    Affirmative,
    /// A field TS12 §3.3.1 displays without labels: one the type displays at every level, a claim
    /// without `display` below level 4, or a payload field the claims metadata omits.
    #[error("{field} has no labels")]
    #[explain(id = "unsupported.labels")]
    Labels {
        /// The field.
        field: FieldPath,
    },
    /// `claims` that is no array (TS12 §3.3.2).
    #[error("claims is no array")]
    #[explain(id = "unsupported.claims_form")]
    ClaimsForm,
    /// A claim without a `path` (TS12 §3.3.2).
    #[error("a claim holds no path")]
    #[explain(id = "unsupported.no_claim_path")]
    NoClaimPath,
    /// A claim whose `path` falls outside the type's field table.
    #[error("{path}: no claim path of the type's field table")]
    #[explain(id = "unsupported.claim_path")]
    ClaimPath {
        /// The path as written, in compact JSON.
        path: String,
    },
    /// A `visualisation` outside TS12 §3.3.1's 1 to 4.
    #[error("{field}: a level outside 1 to 4")]
    #[explain(id = "unsupported.level")]
    Level {
        /// The field.
        field: FieldPath,
    },
    /// A claim's `display` entry without its `lang` and `label` as strings (TS12 §3.3.2).
    #[error("{field}: a display entry outside TS12's form")]
    #[explain(id = "unsupported.claim_labels")]
    ClaimLabels {
        /// The field.
        field: FieldPath,
    },
    /// `ui_labels` that is no object (TS12 §3.3.3).
    #[error("ui_labels is no object")]
    #[explain(id = "unsupported.catalogue_form")]
    CatalogueForm,
    /// A UI label entry without its `lang` and `value` as strings (TS12 §3.3.3).
    #[error("{element}: a UI label entry outside TS12's form")]
    #[explain(id = "unsupported.ui_labels")]
    UiLabels {
        /// The UI element.
        element: UiKey,
    },
}

/// What the display rules ask of a leaf field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shown {
    /// Displayed at every level, and its labels required.
    Always,
    /// Displayed under its claim metadata's level; internal when the claims metadata omits it.
    Declared,
    /// Displayed under its claim metadata's level; a payload holding it needs that metadata.
    WhenHeld,
}

/// A PaSO value type of a leaf field; a field without one is plain text.
#[derive(Debug, Clone, Copy)]
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
#[derive(Debug, Clone, Copy)]
enum Role {
    Object,
    Leaf {
        value_type: Option<ValueType>,
        shown: Shown,
    },
}

/// A field of a type's table.
#[derive(Debug)]
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

/// What a claim's `visualisation` asks (TS12 §3.3.1): levels 1 to 3, or none, display; 4 hides.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Level {
    Displayed,
    Hidden,
}

impl Level {
    fn of(claim: &Node<'_>, field: FieldPath) -> Result<Self, Ts12Unsupported> {
        match claim.get("visualisation") {
            None => Ok(Self::Displayed),
            Some(Node::Number(level)) => match level.as_u64() {
                Some(1..=3) => Ok(Self::Displayed),
                Some(4) => Ok(Self::Hidden),
                _ => Err(Ts12Unsupported::Level { field }),
            },
            Some(_) => Err(Ts12Unsupported::Level { field }),
        }
    }
}

/// A label with its tag as TS12 means it.
#[derive(Debug, Clone)]
struct Label<'d> {
    tag: String,
    text: &'d str,
}

/// A claim of the claims metadata: a field of the type's table, and the labels TS12 §3.3.1 displays
/// it under; `None` for a field that stays internal.
#[derive(Debug, Clone)]
struct Claim<'d> {
    field: &'static Field,
    labels: Option<Vec<Label<'d>>>,
}

/// The UI labels catalogue: the elements PaSO reads, `affirmative_action_label` required.
#[derive(Debug, Clone)]
struct Catalogue<'d> {
    title: Option<Vec<Label<'d>>>,
    affirmative: Vec<Label<'d>>,
    denial: Option<Vec<Label<'d>>>,
    hint: Option<Vec<Label<'d>>>,
}

/// A built-in type's metadata under TS12 §3.3.
#[derive(Debug, Clone)]
pub(crate) struct TypeMetadata<'d> {
    table: &'static [Field],
    claims: Vec<Claim<'d>>,
    catalogue: Catalogue<'d>,
}

impl<'d> TypeMetadata<'d> {
    /// The metadata an entry writes for a type.
    pub(crate) fn parse(
        kind: Ts12Type,
        claims: Option<&'d Node<'d>>,
        ui_labels: Option<&'d Node<'d>>,
    ) -> Result<Self, Ts12Unsupported> {
        let catalogue = ui_labels
            .map(|labels| labels.as_object().ok_or(Ts12Unsupported::CatalogueForm))
            .transpose()?
            .ok_or(Ts12Unsupported::Affirmative)?;
        let affirmative = catalogue
            .get(UiKey::AffirmativeActionLabel.name())
            .ok_or(Ts12Unsupported::Affirmative)?;
        let written = claims
            .map(|claims| claims.as_array().ok_or(Ts12Unsupported::ClaimsForm))
            .transpose()?
            .unwrap_or(&[]);
        let table = fields(kind);
        let claims = written
            .iter()
            .map(|claim| Claim::parse(claim, table))
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(unlabelled) = table.iter().find(|field| {
            field.shown(Shown::Always) && !claims.iter().any(|claim| claim.displays(field.path))
        }) {
            return Err(Ts12Unsupported::Labels {
                field: unlabelled.path,
            });
        }
        let ui_label = |element: UiKey, labels: &'d Node<'d>| {
            read_labels(labels, "value", || Ts12Unsupported::UiLabels { element })
        };
        let optional = |element: UiKey| {
            catalogue
                .get(element.name())
                .map(|labels| ui_label(element, labels))
                .transpose()
        };
        Ok(Self {
            table,
            claims,
            catalogue: Catalogue {
                title: optional(UiKey::TransactionTitle)?,
                affirmative: ui_label(UiKey::AffirmativeActionLabel, affirmative)?,
                denial: optional(UiKey::DenialActionLabel)?,
                hint: optional(UiKey::SecurityHint)?,
            },
        })
    }

    /// Whether a claim displays the field.
    #[cfg(feature = "resolve")]
    pub(crate) fn displays(&self, field: FieldPath) -> bool {
        self.claims.iter().any(|claim| claim.displays(field))
    }
}

impl<'d> Claim<'d> {
    fn parse(claim: &'d Node<'d>, table: &'static [Field]) -> Result<Self, Ts12Unsupported> {
        let written = claim.get("path").ok_or(Ts12Unsupported::NoClaimPath)?;
        let field = field_path(written)
            .and_then(|path| table.iter().find(|field| field.is_at(&path)))
            .ok_or_else(|| Ts12Unsupported::ClaimPath {
                path: written.json_compact().to_string(),
            })?;
        let level = Level::of(claim, field.path)?;
        let display = claim
            .get("display")
            .filter(|display| display.as_array().is_none_or(|labels| !labels.is_empty()));
        if display.is_none() && field.is_leaf() && level != Level::Hidden {
            return Err(Ts12Unsupported::Labels { field: field.path });
        }
        let labels = display
            .filter(|_| level != Level::Hidden || field.shown(Shown::Always))
            .map(|display| {
                read_labels(display, "label", || Ts12Unsupported::ClaimLabels {
                    field: field.path,
                })
            })
            .transpose()?;
        Ok(Self { field, labels })
    }

    fn displays(&self, field: FieldPath) -> bool {
        self.field.path == field && self.labels.is_some()
    }

    /// The claim in PaSO's form.
    fn paso(&self) -> Node<'static> {
        let display = self
            .labels
            .as_deref()
            .map(|labels| label_nodes(labels, claim_entry));
        let value_type = display
            .as_ref()
            .and(self.field.value_type())
            .map(|value_type| Node::String(Cow::Borrowed(value_type)));
        Node::Object(known_object! {
            "path" => Some(path_node(self.field.path)),
            "display" => display,
            "value_type" => value_type,
        })
    }
}

/// The type's metadata in PaSO's form, in the claims metadata's order, each field it omits
/// appended internal.
#[must_use]
pub fn paso_metadata(entry: &BuiltInEntry<'_>) -> Object<'static> {
    let metadata = entry.metadata();
    let omitted = metadata
        .table
        .iter()
        .filter(|field| {
            field.is_leaf()
                && !metadata
                    .claims
                    .iter()
                    .any(|claim| claim.field.path == field.path)
        })
        .map(|field| internal(field.path));
    let claims = metadata
        .claims
        .iter()
        .map(Claim::paso)
        .chain(omitted)
        .collect();
    let catalogue = &metadata.catalogue;
    let ui_label = |labels: &[Label<'_>]| label_nodes(labels, ui_entry);
    let ui = known_object! {
        "transaction_title" => catalogue.title.as_deref().map(ui_label),
        "affirmative_action_label" => Some(ui_label(&catalogue.affirmative)),
        "denial_action_label" => catalogue.denial.as_deref().map(ui_label),
        "security_hint" => catalogue.hint.as_deref().map(ui_label),
    };
    known_object! {
        "claims" => Some(Node::Array(claims)),
        "ui_labels" => Some(Node::Object(ui)),
    }
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
    let metadata = entry.metadata();
    let omitted = metadata.table.iter().find(|field| {
        field.shown(Shown::WhenHeld)
            && field
                .path
                .steps()
                .try_fold(payload, |node, step| node.get(step))
                .is_some()
            && !metadata
                .claims
                .iter()
                .any(|claim| claim.field.path == field.path)
    });
    omitted.map_or(Ok(()), |field| {
        Err(Ts12Unsupported::Labels { field: field.path })
    })
}

/// A claim's path below `payload`; `None` for a path elsewhere or of another form.
fn field_path<'c>(path: &'c Node<'_>) -> Option<Vec<&'c str>> {
    let (first, rest) = path.as_array()?.split_first()?;
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

/// A claim's label in PaSO's form.
fn claim_entry(locale: Node<'static>, label: Node<'static>) -> Object<'static> {
    known_object! { "locale" => Some(locale), "name" => Some(label) }
}

/// A UI element's label in PaSO's form.
fn ui_entry(locale: Node<'static>, label: Node<'static>) -> Object<'static> {
    known_object! { "locale" => Some(locale), "value" => Some(label) }
}

/// Labels in PaSO's form, as `entry` writes each.
fn label_nodes(
    labels: &[Label<'_>],
    entry: fn(Node<'static>, Node<'static>) -> Object<'static>,
) -> Node<'static> {
    Node::Array(
        labels
            .iter()
            .map(|label| {
                Node::Object(entry(
                    Node::String(Cow::Owned(label.tag.clone())),
                    Node::String(Cow::Owned(label.text.to_owned())),
                ))
            })
            .collect(),
    )
}

/// A label array with `lang` read as a tag as TS12 means it and the member `text` as its text; other
/// members, `description` among them, unused.
fn read_labels<'d>(
    array: &'d Node<'d>,
    text: &str,
    refused: impl Fn() -> Ts12Unsupported,
) -> Result<Vec<Label<'d>>, Ts12Unsupported> {
    let items = array.as_array().ok_or_else(&refused)?;
    let tags = items
        .iter()
        .map(|item| item.get("lang").and_then(Node::as_str))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(&refused)?;
    items
        .iter()
        .zip(generic_tags(&tags))
        .map(|(item, tag)| {
            let text = item.get(text).and_then(Node::as_str).ok_or_else(&refused)?;
            Ok(Label { tag, text })
        })
        .collect()
}

/// Each tag as TS12 means it: a tag whose language's generic tag no entry holds takes that generic
/// tag, the first in order when several regions of one language stand alone. PaSO's Lookup then
/// reaches the entry from any list naming the language.
fn generic_tags(tags: &[&str]) -> Vec<String> {
    let mut held: Vec<String> = tags.iter().map(|tag| tag.to_ascii_lowercase()).collect();
    tags.iter()
        .map(|tag| {
            let generic = generic_tag(tag);
            let lowered = generic.to_ascii_lowercase();
            if held.contains(&lowered) {
                (*tag).to_owned()
            } else {
                held.push(lowered);
                generic
            }
        })
        .collect()
}

/// RFC 5646 §2.1's grandfathered tags, irregular and regular, whose subtags carry no meaning apart
/// (§2.2.8).
const GRANDFATHERED: [&str; 26] = [
    "en-GB-oed",
    "i-ami",
    "i-bnn",
    "i-default",
    "i-enochian",
    "i-hak",
    "i-klingon",
    "i-lux",
    "i-mingo",
    "i-navajo",
    "i-pwn",
    "i-tao",
    "i-tay",
    "i-tsu",
    "sgn-BE-FR",
    "sgn-BE-NL",
    "sgn-CH-DE",
    "art-lojban",
    "cel-gaulish",
    "no-bok",
    "no-nyn",
    "zh-guoyu",
    "zh-hakka",
    "zh-min",
    "zh-min-nan",
    "zh-xiang",
];

/// The tag without its region and variants, its script kept (RFC 5646 §2.1): the language, its
/// extended language subtags and its script. A grandfathered or private-use tag stays whole.
fn generic_tag(tag: &str) -> String {
    if GRANDFATHERED
        .iter()
        .any(|grandfathered| grandfathered.eq_ignore_ascii_case(tag))
    {
        return tag.to_owned();
    }
    let mut subtags = tag.split('-');
    let Some(language) = subtags.next().filter(|language| language.len() >= 2) else {
        return tag.to_owned();
    };
    let alphabetic = |subtag: &str| subtag.bytes().all(|byte| byte.is_ascii_alphabetic());
    let mut generic = language.to_owned();
    for subtag in subtags {
        if !alphabetic(subtag) || !matches!(subtag.len(), 3 | 4) {
            break;
        }
        generic.push('-');
        generic.push_str(subtag);
        if subtag.len() == 4 {
            break;
        }
    }
    generic
}
