//! Claim metadata of a definition (PaSO Proof Metadata, Section 3.1): the path into the
//! payload, whether the claim is mandatory, its value type, and its localised names.

use siros_codec::json::Json;
use siros_dcql::{ClaimPath, PathComponent};
use siros_display::{Locale, Localized};

use super::error::{ClaimFault, DefinitionMember, EntryFault};
use super::localized::{self, Localizations};
use super::text::{ClaimName, Description, LabelLength, LabelRole, LabelRules, LabelText};
use super::value_type::{BaseType, LabelFormat, ValueType};
use crate::json::{self, Fields};

/// A claims path pointer resolved against the `payload` of a `transaction_data` entry (Section
/// 3.1; OpenID4VP 1.0, Section 7).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PayloadPath(ClaimPath);

impl PayloadPath {
    /// The pointer of `components`.
    pub(crate) fn new(pointer: ClaimPath) -> Self {
        Self(pointer)
    }

    /// The claims path pointer.
    #[must_use]
    pub fn pointer(&self) -> &ClaimPath {
        &self.0
    }

    /// The components, at least one.
    #[must_use]
    pub fn components(&self) -> &[PathComponent] {
        self.0.components()
    }

    /// The number of `null` components.
    pub(crate) fn wildcards(&self) -> usize {
        self.components()
            .iter()
            .filter(|c| **c == PathComponent::Null)
            .count()
    }
}

/// Whether the payload must hold a claim (`mandatory`, OpenID4VCI 1.0, Appendix B.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mandatory {
    /// `mandatory: true`.
    Required,
    /// `mandatory: false`, or absent.
    Optional,
}

/// A visualisation level of EC TS12 v1.0.1, Section 3.3.1, most prominent first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Prominence {
    /// `1`: shown prominently on the main confirmation screen.
    Prominent,
    /// `2`: shown on the main confirmation screen.
    Main,
    /// `3`, the default: shown, possibly on a supplementary screen.
    Supplementary,
    /// `4`: may be omitted.
    Omittable,
}

impl Prominence {
    /// The level of the `visualisation` value `value`.
    pub(crate) fn of(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Prominent),
            2 => Some(Self::Main),
            3 => Some(Self::Supplementary),
            4 => Some(Self::Omittable),
            _ => None,
        }
    }

    /// The `visualisation` value.
    #[must_use]
    pub fn level(self) -> u8 {
        match self {
            Self::Prominent => 1,
            Self::Main => 2,
            Self::Supplementary => 3,
            Self::Omittable => 4,
        }
    }
}

/// A `display` entry of a claim: its locale, its `name` and how the name is formatted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimDisplay {
    pub(crate) locale: Option<Locale>,
    pub(crate) name: LabelText<ClaimName>,
    pub(crate) format: LabelFormat,
    pub(crate) description: Option<Description>,
}

impl Localized for ClaimDisplay {
    fn locale(&self) -> Option<&Locale> {
        self.locale.as_ref()
    }
}

impl ClaimDisplay {
    /// The `name`.
    #[must_use]
    pub fn name(&self) -> &LabelText<ClaimName> {
        &self.name
    }

    /// How the name is formatted.
    #[must_use]
    pub fn format(&self) -> LabelFormat {
        self.format
    }

    /// The `description`, which TS12 type metadata carries.
    #[must_use]
    pub fn description(&self) -> Option<&Description> {
        self.description.as_ref()
    }

    /// The entry of `fields` under `rules`: `locale`, `name`, and `display_type` (Sections 3.1
    /// and 3.3), and the `description` of SD-JWT VC claim metadata. `None` for an entry whose
    /// `display_type` is none of `mini_markdown` and `template:mini_markdown`: PaSO View,
    /// Section 3 excludes it from the locale function.
    pub(crate) fn parse(mut fields: Fields, rules: LabelRules) -> Result<Option<Self>, EntryFault> {
        let locale = localized::locale(&mut fields)?;
        let name = localized::required_text(&mut fields, DefinitionMember::Name)?;
        let format = match label_format(&mut fields, DefinitionMember::DisplayType) {
            Ok(format) => format,
            Err(EntryFault::Format(_)) => return Ok(None),
            Err(fault) => return Err(fault),
        };
        let description = localized::optional_text(&mut fields, DefinitionMember::Description)?
            .map(|text| {
                Description::parse(&text)
                    .map_err(|fault| EntryFault::Text(DefinitionMember::Description, fault))
            })
            .transpose()?;
        Ok(Some(Self {
            locale,
            name: label(&name, format, DefinitionMember::Name, rules)?,
            format,
            description,
        }))
    }
}

/// The label format the member `member` of a label entry names: plain text when absent.
///
/// # Errors
///
/// [`EntryFault::Format`] for a type other than `mini_markdown` and `template:mini_markdown`.
pub(crate) fn label_format(
    fields: &mut Fields,
    member: DefinitionMember,
) -> Result<LabelFormat, EntryFault> {
    match localized::optional_text(fields, member)? {
        None => Ok(LabelFormat::Plain),
        Some(text) => LabelFormat::parse(&text).ok_or(EntryFault::Format(text)),
    }
}

/// The label `text` of role `R` under `rules`, formatted by `format`.
pub(crate) fn label<R: LabelRole>(
    text: &str,
    format: LabelFormat,
    member: DefinitionMember,
    rules: LabelRules,
) -> Result<LabelText<R>, EntryFault> {
    let length = match format {
        LabelFormat::TemplateMiniMarkdown => LabelLength::Template,
        LabelFormat::Plain | LabelFormat::MiniMarkdown => LabelLength::Final,
    };
    LabelText::parse(text, length, rules).map_err(|fault| EntryFault::Text(member, fault))
}

/// A claim metadata object (Section 3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimDefinition {
    pub(crate) path: PayloadPath,
    pub(crate) mandatory: Mandatory,
    pub(crate) value_type: Option<ValueType>,
    pub(crate) display: Option<Localizations<ClaimDisplay>>,
    pub(crate) prominence: Option<Prominence>,
}

impl ClaimDefinition {
    /// The claim of `value` under `rules`: `path`, `mandatory`, `value_type` only with
    /// `display`, and a `label_only` claim never mandatory (Section 3.1; PaSO View, Section 3);
    /// under TS12's rules, `visualisation` (EC TS12 v1.0.1, Section 3.3.2). Other members are
    /// ignored.
    pub(crate) fn parse(value: Json, rules: LabelRules) -> Result<Self, ClaimFault> {
        let mut fields = json::object(value).map_err(|_| ClaimFault::NotObject)?;
        let path = path(&mut fields)?;
        let mandatory = match fields
            .optional(DefinitionMember::Mandatory.as_str(), json::boolean)
            .map_err(|fault| ClaimFault::Member(DefinitionMember::Mandatory, fault))?
        {
            Some(true) => Mandatory::Required,
            Some(false) | None => Mandatory::Optional,
        };
        let value_type = fields
            .optional(DefinitionMember::ValueType.as_str(), json::text)
            .map_err(|fault| ClaimFault::Member(DefinitionMember::ValueType, fault))?
            .map(|name| ValueType::parse(&name).ok_or(ClaimFault::ValueTypeUnknown(name)))
            .transpose()?;
        let display = fields
            .take(DefinitionMember::Display.as_str())
            .map(|display| Localizations::parse(display, |entry| ClaimDisplay::parse(entry, rules)))
            .transpose()
            .map_err(ClaimFault::Display)?;
        let prominence = match rules {
            LabelRules::Ts12 => visualisation(&mut fields)?,
            LabelRules::Paso => None,
        };
        Self::new(path, mandatory, value_type, display, prominence)
    }

    /// The claim of its parts, checked against Section 3.1 and PaSO View, Section 3.
    pub(crate) fn new(
        path: PayloadPath,
        mandatory: Mandatory,
        value_type: Option<ValueType>,
        display: Option<Localizations<ClaimDisplay>>,
        prominence: Option<Prominence>,
    ) -> Result<Self, ClaimFault> {
        if value_type.is_some() && display.is_none() {
            return Err(ClaimFault::ValueTypeWithoutDisplay);
        }
        if value_type.map(ValueType::base) == Some(BaseType::LabelOnly)
            && mandatory == Mandatory::Required
        {
            return Err(ClaimFault::LabelOnlyMandatory);
        }
        Ok(Self {
            path,
            mandatory,
            value_type,
            display,
            prominence,
        })
    }

    /// The claim with its `display` array reduced to `entry`.
    pub(crate) fn in_one_locale(&self, entry: ClaimDisplay) -> Self {
        Self {
            display: Some(Localizations::single(entry)),
            ..self.clone()
        }
    }

    /// The path.
    #[must_use]
    pub fn path(&self) -> &PayloadPath {
        &self.path
    }

    /// Whether the payload must hold the claim.
    #[must_use]
    pub fn mandatory(&self) -> Mandatory {
        self.mandatory
    }

    /// The value type; `None` for plain text.
    #[must_use]
    pub fn value_type(&self) -> Option<ValueType> {
        self.value_type
    }

    /// The `display` array; `None` for an internal claim.
    #[must_use]
    pub fn display(&self) -> Option<&Localizations<ClaimDisplay>> {
        self.display.as_ref()
    }

    /// The `visualisation` level TS12 type metadata gives.
    #[must_use]
    pub fn prominence(&self) -> Option<Prominence> {
        self.prominence
    }
}

/// The optional `visualisation` of a claim: an integer from 1 to 4 (EC TS12 v1.0.1, Section
/// 3.3.2).
pub(crate) fn visualisation(fields: &mut Fields) -> Result<Option<Prominence>, ClaimFault> {
    fields
        .optional(DefinitionMember::Visualisation.as_str(), json::integer)
        .map_err(|fault| ClaimFault::Member(DefinitionMember::Visualisation, fault))?
        .map(|level| {
            level
                .number()
                .as_u64()
                .and_then(Prominence::of)
                .ok_or(ClaimFault::Visualisation)
        })
        .transpose()
}

/// The required `path` of a claim: a claims path pointer of keys, indexes and `null`.
pub(crate) fn path(fields: &mut Fields) -> Result<PayloadPath, ClaimFault> {
    let member = |fault| ClaimFault::Member(DefinitionMember::Path, fault);
    let components = fields
        .require(DefinitionMember::Path.as_str())
        .and_then(json::array)
        .map_err(member)?;
    pointer(components).map(PayloadPath::new)
}

/// The claims path pointer of the JSON `components`.
pub(crate) fn pointer(components: Vec<Json>) -> Result<ClaimPath, ClaimFault> {
    let components = components
        .into_iter()
        .enumerate()
        .map(|(at, component)| match component {
            Json::String(key) => Ok(PathComponent::Key(key)),
            Json::Null => Ok(PathComponent::Null),
            Json::Number(n) => n
                .number()
                .as_u64()
                .map(PathComponent::Index)
                .ok_or(ClaimFault::Path(component_fault(at))),
            Json::Bool(_) | Json::Array(_) | Json::Object(_) => {
                Err(ClaimFault::Path(component_fault(at)))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    ClaimPath::new(components).map_err(ClaimFault::Path)
}

fn component_fault(at: usize) -> siros_dcql::ClaimPathError {
    siros_dcql::ClaimPathError::Component(siros_dcql::ComponentIndex::new(at))
}
