//! A transaction data type's metadata (Proof Metadata §3): its claims (§3.1) and the UI labels
//! the wallet recognises (§3.2), parsed under the label and structural constraints of §3.3.
//! Metadata that breaks a constraint makes the type unsupported by the credential; a displayed
//! claim's value type the wallet does not support makes the entry not compatible (View §3).

use std::fmt;
use std::num::NonZeroUsize;

use siros_i18n::Message;
use siros_openid4vp::claims::ClaimPath;
use siros_openid4vp::json::Node;
use siros_openid4vp::refusal::{ReprItem, ReprOption};

use crate::conform::ClaimIndex;
use crate::labels::{LabelLimits, LabelSlot, LabelText, LabelViolation};
use crate::mandate::MandateLabel;
use crate::outcome::{NotCompatible, Outcome, Unsupported};
use crate::path::claim_text;
use crate::value::{FormattedKind, ValueKind};

/// A UI element identifier the wallet recognises (Proof Metadata §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UiKey {
    /// `transaction_title`.
    TransactionTitle,
    /// `affirmative_action_label`.
    AffirmativeActionLabel,
    /// `denial_action_label`.
    DenialActionLabel,
    /// `security_hint`.
    SecurityHint,
}

impl UiKey {
    const ALL: [Self; 4] = [
        Self::TransactionTitle,
        Self::AffirmativeActionLabel,
        Self::DenialActionLabel,
        Self::SecurityHint,
    ];

    /// The identifier.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TransactionTitle => "transaction_title",
            Self::AffirmativeActionLabel => "affirmative_action_label",
            Self::DenialActionLabel => "denial_action_label",
            Self::SecurityHint => "security_hint",
        }
    }

    /// The UI element of an identifier the wallet recognises.
    #[must_use]
    pub fn of(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|key| key.name() == name)
    }

    /// Where its labels show.
    #[must_use]
    pub const fn slot(self) -> LabelSlot {
        match self {
            Self::TransactionTitle => LabelSlot::Title,
            Self::AffirmativeActionLabel => LabelSlot::Affirmative,
            Self::DenialActionLabel => LabelSlot::Denial,
            Self::SecurityHint => LabelSlot::Hint,
        }
    }
}

impl fmt::Display for UiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A display array, the place an error names: a claim's `display` or a UI label's entries. An
/// error's argument writes it in English through `Display`; a wallet words it through its
/// statement.
#[derive(Debug, Clone, PartialEq, Eq, Message)]
pub enum ArrayAt {
    /// The `display` of the claim at a path.
    #[message(id = "array_at.claim")]
    Claim {
        /// The claim's path.
        path: ReprItem,
    },
    /// A UI label's entries.
    #[message(id = "array_at.ui")]
    Ui {
        /// The UI label.
        key: UiKey,
    },
}

impl fmt::Display for ArrayAt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Claim { path } => write!(f, "claim {path} display"),
            Self::Ui { key } => write!(f, "ui_labels.{key}"),
        }
    }
}

impl ArrayAt {
    /// The rule a label of this array breaks as written.
    fn label(&self, violation: LabelViolation) -> Unsupported {
        match self {
            Self::Claim { path } => Unsupported::ClaimLabel {
                claim: path.clone(),
                violation,
            },
            Self::Ui { key } => Unsupported::UiLabel {
                key: *key,
                violation,
            },
        }
    }
}

/// The character a template label's conversion reads its placeholders as ([`crate::view`]): a
/// template label that holds it is unsupported.
pub(crate) const RESERVED: char = '\u{FDD0}';

/// A display entry's locale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryLocale<'m> {
    /// A language tag as written.
    Tagged(&'m str),
    /// No locale: the array's default entry.
    Default,
}

/// A label as its entry types it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelForm<'m> {
    /// Plain text, meeting §3.3.
    Plain(LabelText<'m>),
    /// `mini_markdown`, meeting §3.3.
    Markdown(LabelText<'m>),
    /// `template:mini_markdown`: §3.3 applies once interpolated.
    Template(&'m str),
    /// A Mandate claim's label: a text of the wallet's own, which the rulebook names.
    Own(MandateLabel),
}

/// One entry of a display array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Localized<'m> {
    /// Its locale.
    pub locale: EntryLocale<'m>,
    /// Its label.
    pub label: LabelForm<'m>,
}

/// A non-empty display array, each locale once case-insensitively, at most one default entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayArray<'m>(Vec<Localized<'m>>);

/// Which label types an array admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Typing {
    /// `mini_markdown` and `template:mini_markdown`.
    Text,
    /// None: the `security_hint` is plain text.
    Plain,
}

/// How a JSON array of display entries reads: the member holding the text, the member typing
/// it, the types admitted, its labels' limit and how a refusal names it.
struct ArrayShape {
    text: &'static str,
    typed_by: &'static str,
    typing: Typing,
    limit: NonZeroUsize,
    at: ArrayAt,
}

impl<'m> DisplayArray<'m> {
    /// The entries in their order.
    #[must_use]
    pub fn entries(&self) -> &[Localized<'m>] {
        &self.0
    }

    /// An array the wallet builds from entries known to meet §3.3.
    pub(crate) fn built(entries: Vec<Localized<'m>>) -> Self {
        Self(entries)
    }

    /// Parses an array: every entry's structure first, then each fixed label against §3.3.
    fn parse(node: &'m Node<'m>, shape: &ArrayShape) -> Result<Self, Unsupported> {
        let items = node
            .as_array()
            .filter(|items| !items.is_empty())
            .ok_or_else(|| Unsupported::EmptyArray {
                at: shape.at.clone(),
            })?;
        let mut seen: Vec<String> = Vec::new();
        let mut defaults = 0usize;
        let mut raw: Vec<(EntryLocale<'m>, &'m str, RawType)> = Vec::new();
        for item in items {
            let text = item.get(shape.text).and_then(Node::as_str).ok_or_else(|| {
                Unsupported::EntryWithoutText {
                    at: shape.at.clone(),
                    member: shape.text,
                }
            })?;
            let typed = RawType::read(item.get(shape.typed_by), shape)?;
            let locale = match item.get("locale") {
                None => {
                    defaults += 1;
                    EntryLocale::Default
                }
                Some(Node::Null) => {
                    return Err(Unsupported::NullLocale {
                        at: shape.at.clone(),
                    });
                }
                Some(Node::String(tag)) if !seen.contains(&tag.to_lowercase()) => {
                    seen.push(tag.to_lowercase());
                    EntryLocale::Tagged(tag)
                }
                Some(other) => {
                    return Err(Unsupported::LocaleRepeated {
                        at: shape.at.clone(),
                        locale: ReprItem::repr(other),
                    });
                }
            };
            raw.push((locale, text, typed));
        }
        if defaults > 1 {
            return Err(Unsupported::DefaultTwice {
                at: shape.at.clone(),
            });
        }
        raw.into_iter()
            .map(|(locale, text, typed)| {
                let checked = || LabelText::parse(text, shape.limit).map_err(|v| shape.at.label(v));
                let label = match typed {
                    RawType::Plain => LabelForm::Plain(checked()?),
                    RawType::Markdown => LabelForm::Markdown(checked()?),
                    RawType::Template if text.contains([RESERVED, '\0']) => {
                        return Err(Unsupported::Reserved {
                            at: shape.at.clone(),
                        });
                    }
                    RawType::Template => LabelForm::Template(text),
                };
                Ok(Localized { locale, label })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }
}

/// A label type an entry admits.
#[derive(Debug, Clone, Copy)]
enum RawType {
    Plain,
    Markdown,
    Template,
}

impl RawType {
    fn read(typed: Option<&Node<'_>>, shape: &ArrayShape) -> Result<Self, Unsupported> {
        let refused = |node: &Node<'_>| Unsupported::LabelType {
            at: shape.at.clone(),
            member: shape.typed_by,
            written: ReprItem::repr(node),
        };
        match (typed, shape.typing) {
            (None, _) => Ok(Self::Plain),
            (Some(Node::String(kind)), Typing::Text) if kind == "mini_markdown" => {
                Ok(Self::Markdown)
            }
            (Some(Node::String(kind)), Typing::Text) if kind == "template:mini_markdown" => {
                Ok(Self::Template)
            }
            (Some(node), _) => Err(refused(node)),
        }
    }
}

/// How a displayed claim's value is formatted (View §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueType {
    /// No `value_type`: plain text, a string.
    Plain,
    /// A value type.
    Kind(ValueKind),
    /// `label_only`: the label alone, any JSON value.
    LabelOnly,
    /// `template:` and a text-producing value type: interpolated, then formatted by it.
    Template(FormattedKind),
}

const KINDS: [(&str, ValueKind); 10] = [
    ("boolean", ValueKind::Formatted(FormattedKind::Boolean)),
    ("frequency", ValueKind::Formatted(FormattedKind::Frequency)),
    ("image", ValueKind::Image),
    ("iso_date", ValueKind::Formatted(FormattedKind::Date)),
    ("iso_time", ValueKind::Formatted(FormattedKind::Time)),
    (
        "iso_date_time",
        ValueKind::Formatted(FormattedKind::DateTime),
    ),
    (
        "iso_currency",
        ValueKind::Formatted(FormattedKind::Currency),
    ),
    (
        "iso_currency_amount",
        ValueKind::Formatted(FormattedKind::CurrencyAmount),
    ),
    (
        "mini_markdown",
        ValueKind::Formatted(FormattedKind::MiniMarkdown),
    ),
    ("url", ValueKind::Formatted(FormattedKind::Url)),
];

impl ValueType {
    /// The value type a claim's `value_type` names; `None` for one the wallet does not support.
    /// A template's inner type produces text: an image is resolved before the locale its
    /// interpolation needs is known.
    #[must_use]
    pub fn parse(written: Option<&Node<'_>>) -> Option<Self> {
        let kind = |name: &str| {
            KINDS
                .iter()
                .find(|(known, _)| *known == name)
                .map(|(_, kind)| *kind)
        };
        match written {
            None | Some(Node::Null) => Some(Self::Plain),
            Some(Node::String(name)) if name == "label_only" => Some(Self::LabelOnly),
            Some(Node::String(name)) => match name.strip_prefix("template:") {
                Some(inner) => match kind(inner)? {
                    ValueKind::Formatted(inner) => Some(Self::Template(inner)),
                    ValueKind::Image => None,
                },
                None => kind(name).map(Self::Kind),
            },
            Some(_) => None,
        }
    }

    /// The kind its rendered value has; `None` for `label_only`.
    #[must_use]
    pub const fn rendered(self) -> Option<ValueKind> {
        match self {
            Self::Plain => Some(ValueKind::Formatted(FormattedKind::Text)),
            Self::Kind(kind) => Some(kind),
            Self::LabelOnly => None,
            Self::Template(inner) => Some(ValueKind::Formatted(inner)),
        }
    }
}

/// The `value_type` naming a kind, `plain text` for text.
#[must_use]
pub fn kind_name(kind: ValueKind) -> &'static str {
    KINDS
        .iter()
        .find(|(_, known)| *known == kind)
        .map_or("plain text", |(name, _)| name)
}

/// Whether a claim is `mandatory`: written `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mandatory {
    /// `"mandatory": true`.
    Yes,
    /// Anything else.
    No,
}

/// A claim the metadata displays: its labels and how its value is formatted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Displayed<'m> {
    /// The labels by locale.
    pub names: DisplayArray<'m>,
    /// The value type.
    pub value: ValueType,
}

/// One claim's metadata (Proof Metadata §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimMeta<'m> {
    /// The claims path pointer over the payload.
    pub path: ClaimPath<'m>,
    /// Whether it is mandatory.
    pub mandatory: Mandatory,
    /// How it is displayed; `None` for an internal claim.
    pub display: Option<Displayed<'m>>,
}

/// One UI element's labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiLabel<'m> {
    /// The UI element.
    pub key: UiKey,
    /// Its labels by locale.
    pub entries: DisplayArray<'m>,
}

/// A transaction data type's metadata: its claims and the UI labels the wallet recognises, in
/// the order written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata<'m> {
    /// The claims.
    pub claims: Vec<ClaimMeta<'m>>,
    /// The recognised UI labels.
    pub ui: Vec<UiLabel<'m>>,
}

impl<'m> Metadata<'m> {
    /// Parses a type's metadata in the order of Proof Metadata §3.1-3.3: the claims, each
    /// claim's path, display array, labels, `label_only` rule and value type; then the UI
    /// labels, unrecognised identifiers ignored (§3.2). Each label meets `limits`.
    pub fn parse(node: &'m Node<'m>, limits: LabelLimits) -> Result<Self, Outcome> {
        let claims = node
            .get("claims")
            .and_then(Node::as_array)
            .ok_or(Unsupported::NoClaims)?;
        if claims.len() > 100 {
            return Err(Unsupported::TooManyClaims {
                claims: claims.len(),
            }
            .into());
        }
        let mut parsed: Vec<ClaimMeta<'m>> = Vec::with_capacity(claims.len());
        for (k, claim) in claims.iter().enumerate() {
            let path =
                claim
                    .get("path")
                    .and_then(ClaimPath::parse)
                    .ok_or(Unsupported::InvalidPath {
                        claim: ClaimIndex(k),
                    })?;
            if parsed.iter().any(|earlier| earlier.path == path) {
                return Err(Unsupported::PathTwice {
                    path: claim_text(path.steps()),
                }
                .into());
            }
            let mandatory = if claim.get("mandatory") == Some(&Node::Bool(true)) {
                Mandatory::Yes
            } else {
                Mandatory::No
            };
            let display = match claim.get("display") {
                None if claim.get("value_type").is_some() => {
                    return Err(Unsupported::ValueTypeWithoutDisplay {
                        claim: claim_text(path.steps()),
                    }
                    .into());
                }
                None => None,
                Some(display) => Some(Displayed::parse(claim, display, &path, mandatory, limits)?),
            };
            parsed.push(ClaimMeta {
                path,
                mandatory,
                display,
            });
        }
        let ui = match node.get("ui_labels") {
            None => Vec::new(),
            Some(labels) => UiLabel::parse_all(labels, limits)?,
        };
        Ok(Self { claims: parsed, ui })
    }
}

impl<'m> Displayed<'m> {
    fn parse(
        claim: &'m Node<'m>,
        display: &'m Node<'m>,
        path: &ClaimPath<'m>,
        mandatory: Mandatory,
        limits: LabelLimits,
    ) -> Result<Self, Outcome> {
        let names = DisplayArray::parse(
            display,
            &ArrayShape {
                text: "name",
                typed_by: "display_type",
                typing: Typing::Text,
                limit: limits.of(LabelSlot::ClaimName),
                at: ArrayAt::Claim {
                    path: claim_text(path.steps()),
                },
            },
        )?;
        let written = claim.get("value_type");
        let value = ValueType::parse(written);
        if value == Some(ValueType::LabelOnly) && mandatory == Mandatory::Yes {
            return Err(Unsupported::MandatoryLabelOnly {
                claim: claim_text(path.steps()),
            }
            .into());
        }
        let value = value.ok_or_else(|| NotCompatible::ValueType {
            path: claim_text(path.steps()),
            written: ReprOption::of(written),
        })?;
        Ok(Self { names, value })
    }
}

impl<'m> UiLabel<'m> {
    /// The recognised UI labels of a `ui_labels` object, in the order written.
    pub(crate) fn parse_all(
        node: &'m Node<'m>,
        limits: LabelLimits,
    ) -> Result<Vec<Self>, Unsupported> {
        let object = node.as_object().ok_or(Unsupported::UiLabelsNotObject)?;
        object
            .members()
            .iter()
            .filter_map(|member| UiKey::of(&member.name).map(|key| (key, &member.value)))
            .map(|(key, value)| Self::parse(key, value, limits))
            .collect()
    }

    /// One UI element's labels.
    pub(crate) fn parse(
        key: UiKey,
        node: &'m Node<'m>,
        limits: LabelLimits,
    ) -> Result<Self, Unsupported> {
        let typing = if key == UiKey::SecurityHint {
            Typing::Plain
        } else {
            Typing::Text
        };
        let entries = DisplayArray::parse(
            node,
            &ArrayShape {
                text: "value",
                typed_by: "value_type",
                typing,
                limit: limits.of(key.slot()),
                at: ArrayAt::Ui { key },
            },
        )?;
        Ok(Self { key, entries })
    }
}
