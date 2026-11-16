//! The host's configuration of transaction data types: definitions the wallet holds for the
//! credential types they name. It serves only credentials without transaction metadata of their
//! own.

use siros_codec::json::{Json, JsonFault};
use siros_codec::member::{ArrayIndex, MemberFault};
#[cfg(feature = "wallet")]
use siros_credential::{Credential, CredentialType};
use siros_dcql::{DocType, Vct};

use crate::definition::{Definition, DefinitionError};
use crate::json::{self, Fields};
use crate::type_id::{EmptyTypeId, TypeId};

/// A credential type a configured definition applies to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConfiguredType {
    /// An SD-JWT VC `vct`.
    Vct(Vct),
    /// An mdoc `docType`.
    DocType(DocType),
}

/// A configured definition: the transaction data type, the credential types it applies to, and
/// the definition.
#[derive(Debug, Clone, PartialEq)]
pub struct Configured {
    type_id: TypeId,
    applies_to: Vec<ConfiguredType>,
    definition: Definition,
}

/// The host's configured definitions. No two define one type for one credential type.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Configuration(Vec<Configured>);

/// A member of a configured definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigurationMember {
    /// `type`.
    Type,
    /// `vct_values`.
    VctValues,
    /// `doctype_values`.
    DoctypeValues,
    /// `definition`.
    Definition,
}

impl ConfigurationMember {
    /// The member's name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Type => "type",
            Self::VctValues => "vct_values",
            Self::DoctypeValues => "doctype_values",
            Self::Definition => "definition",
        }
    }
}

/// Why a configuration does not read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum ConfigurationError {
    /// The text is no JSON document the strict reader holds.
    Json(#[source] JsonFault),
    /// The document is no JSON array.
    NotArray,
    /// The configured definition at this position breaks a rule.
    Entry(ArrayIndex, #[source] ConfiguredFault),
    /// The entry at this position defines a type for a credential type an earlier entry
    /// defines it for.
    Repeated(ArrayIndex),
}

/// Why a configured definition breaks its rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfiguredFault {
    /// The entry is no JSON object.
    #[error("the entry is no JSON object")]
    NotObject,
    /// A member breaks its rule.
    #[error("the member `{}` breaks its rule", .0.as_str())]
    Member(ConfigurationMember, #[source] MemberFault),
    /// `type` is the empty string.
    #[error("`type` is the empty string")]
    TypeEmpty,
    /// The entry names no credential type.
    #[error("the entry names no credential type")]
    NoCredentialType,
    /// The definition breaks PaSO Proof Metadata, Section 3.
    #[error("the definition breaks PaSO Proof Metadata, Section 3")]
    Definition(#[source] DefinitionError),
    /// The entry has a member other than its four.
    #[error("the entry has the member {0:?}, other than its four")]
    MemberUnknown(String),
}

impl ConfigurationError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Json(_) | Self::NotArray => "configuration_malformed",
            Self::Entry(_, ConfiguredFault::Definition(error)) => error.code(),
            Self::Entry(..) => "configuration_entry_malformed",
            Self::Repeated(_) => "configuration_entry_repeated",
        }
    }
}

impl Configuration {
    /// The configuration of the JSON text `text`: an array of entries `{type, vct_values,
    /// doctype_values, definition}`, `definition` of the form of PaSO Proof Metadata, Section 3,
    /// each entry naming at least one credential type.
    ///
    /// # Errors
    ///
    /// [`ConfigurationError`]: the first rule `text` breaks.
    pub fn parse(text: &str) -> Result<Self, ConfigurationError> {
        let items = match Json::parse_unique(text.as_bytes()).map_err(ConfigurationError::Json)? {
            Json::Array(items) => items,
            _ => return Err(ConfigurationError::NotArray),
        };
        let mut entries: Vec<Configured> = Vec::with_capacity(items.len());
        for (at, item) in items.into_iter().enumerate() {
            let index = ArrayIndex::new(at);
            let entry =
                Configured::parse(item).map_err(|fault| ConfigurationError::Entry(index, fault))?;
            let repeated = entries.iter().any(|earlier| {
                earlier.type_id == entry.type_id
                    && earlier
                        .applies_to
                        .iter()
                        .any(|t| entry.applies_to.contains(t))
            });
            if repeated {
                return Err(ConfigurationError::Repeated(index));
            }
            entries.push(entry);
        }
        Ok(Self(entries))
    }

    /// The definition of `type_id` for `credential`'s type.
    #[cfg(feature = "wallet")]
    pub(crate) fn definition(
        &self,
        type_id: &TypeId,
        credential: &Credential,
    ) -> Option<&Definition> {
        self.applying_to(credential)
            .find(|entry| entry.type_id == *type_id)
            .map(|entry| &entry.definition)
    }

    /// The types configured for `credential`'s type, in the configuration's order.
    #[cfg(feature = "wallet")]
    pub(crate) fn types<'c>(&'c self, credential: &Credential) -> impl Iterator<Item = &'c TypeId> {
        self.applying_to(credential).map(|entry| &entry.type_id)
    }

    /// The entries that apply to `credential`'s type.
    #[cfg(feature = "wallet")]
    fn applying_to<'c>(&'c self, credential: &Credential) -> impl Iterator<Item = &'c Configured> {
        let own = match credential.credential_type() {
            CredentialType::Vct(vct) => ConfiguredType::Vct(vct.clone()),
            CredentialType::DocType(doc_type) => ConfiguredType::DocType(doc_type.clone()),
        };
        self.0
            .iter()
            .filter(move |entry| entry.applies_to.contains(&own))
    }
}

impl Configured {
    fn parse(value: Json) -> Result<Self, ConfiguredFault> {
        let mut fields = json::object(value).map_err(|_| ConfiguredFault::NotObject)?;
        let member = |member| move |fault| ConfiguredFault::Member(member, fault);
        let type_id = fields
            .require("type")
            .and_then(json::text)
            .map_err(member(ConfigurationMember::Type))?;
        let type_id = TypeId::parse(&type_id).map_err(|EmptyTypeId| ConfiguredFault::TypeEmpty)?;
        let mut applies_to = names(&mut fields, "vct_values", ConfigurationMember::VctValues)?
            .into_iter()
            .map(|name| ConfiguredType::Vct(Vct::new(&name)))
            .collect::<Vec<_>>();
        applies_to.extend(
            names(
                &mut fields,
                "doctype_values",
                ConfigurationMember::DoctypeValues,
            )?
            .into_iter()
            .map(|name| ConfiguredType::DocType(DocType::new(&name))),
        );
        if applies_to.is_empty() {
            return Err(ConfiguredFault::NoCredentialType);
        }
        let definition = fields
            .require("definition")
            .map_err(member(ConfigurationMember::Definition))?;
        let definition = Definition::parse(definition, crate::definition::LabelRules::Paso)
            .map_err(ConfiguredFault::Definition)?;
        if let Some(unknown) = fields.first_left() {
            return Err(ConfiguredFault::MemberUnknown(unknown.to_owned()));
        }
        Ok(Self {
            type_id,
            applies_to,
            definition,
        })
    }
}

/// The optional array of strings `name`.
fn names(
    fields: &mut Fields,
    name: &str,
    member: ConfigurationMember,
) -> Result<Vec<String>, ConfiguredFault> {
    let fault = |fault| ConfiguredFault::Member(member, fault);
    fields
        .optional(name, json::array)
        .map_err(fault)?
        .unwrap_or_default()
        .into_iter()
        .map(|item| json::text(item).map_err(fault))
        .collect()
}
