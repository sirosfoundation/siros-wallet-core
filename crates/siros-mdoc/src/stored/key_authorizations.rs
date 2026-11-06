//! The elements the device key may sign in `DeviceSigned` (ISO/IEC 18013-5, 9.1.2.4).

use rustc_hash::FxHashSet;
use siros_openid4vp::cbor::Value;
use siros_openid4vp::json::{Distinct, Named};

use super::item::Read as _;

use super::error::{CborError, KeyAuthorizationsFault, NamesFault};
use super::mso::{non_empty_array, non_empty_map};
use super::names::{ElementIdentifier, NameSpace};

/// The elements the device key may sign: every element of the namespaces of `nameSpaces`, and
/// the elements `dataElements` names, in the issuer's order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyAuthorizations {
    name_spaces: Vec<NameSpace>,
    data_elements: Distinct<DataElements>,
}

/// The elements of one namespace the device key may sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataElements {
    name_space: NameSpace,
    identifiers: Vec<ElementIdentifier>,
}

impl DataElements {
    /// The namespace.
    #[must_use]
    pub fn name_space(&self) -> &NameSpace {
        &self.name_space
    }

    /// Its element identifiers, each once.
    #[must_use]
    pub fn identifiers(&self) -> &[ElementIdentifier] {
        &self.identifiers
    }
}

impl Named for DataElements {
    fn name(&self) -> &str {
        self.name_space.as_str()
    }
}

impl KeyAuthorizations {
    /// `KeyAuthorizations = {? "nameSpaces": [+ NameSpace], ? "dataElements": {+ NameSpace =>
    /// [+ DataElementIdentifier]}}`. A namespace authorized whole is not also in `dataElements`.
    pub(crate) fn read(item: Option<&Value>) -> Result<Self, KeyAuthorizationsFault> {
        let Some(item) = item else {
            return Ok(Self::default());
        };
        if item.as_map().is_none() {
            return Err(KeyAuthorizationsFault::NotMap);
        }
        let name_spaces = match item.get("nameSpaces") {
            Some(names) => {
                names_once(names, NameSpace::new).map_err(KeyAuthorizationsFault::NameSpaces)?
            }
            None => Vec::new(),
        };
        let data_elements = match item.get("dataElements") {
            Some(elements) => read_data_elements(elements, &name_spaces)?,
            None => Distinct::default(),
        };
        Ok(Self {
            name_spaces,
            data_elements,
        })
    }

    /// Whether the device key may sign `identifier` of `name_space` (ISO/IEC 18013-5, 9.1.2.4).
    #[must_use]
    pub fn authorizes(&self, name_space: &NameSpace, identifier: &ElementIdentifier) -> bool {
        self.name_spaces.contains(name_space)
            || self
                .data_elements
                .get(name_space.as_str())
                .is_some_and(|elements| elements.identifiers.contains(identifier))
    }

    /// The namespaces authorized whole.
    #[must_use]
    pub fn name_spaces(&self) -> &[NameSpace] {
        &self.name_spaces
    }

    /// The elements authorized, per namespace.
    #[must_use]
    pub fn data_elements(&self) -> &Distinct<DataElements> {
        &self.data_elements
    }
}

/// `dataElements`, none of whose namespaces `name_spaces` authorizes whole.
fn read_data_elements(
    elements: &Value,
    name_spaces: &[NameSpace],
) -> Result<Distinct<DataElements>, KeyAuthorizationsFault> {
    let entries = non_empty_map(Some(elements)).map_err(KeyAuthorizationsFault::DataElements)?;
    let mut data_elements = Vec::with_capacity(entries.len());
    for (name_space, identifiers) in entries {
        let name_space = NameSpace::new(
            name_space
                .as_text()
                .ok_or(KeyAuthorizationsFault::NameSpace)?,
        );
        if name_spaces.contains(&name_space) {
            return Err(KeyAuthorizationsFault::Overlap(name_space));
        }
        let identifiers = names_once(identifiers, ElementIdentifier::new)
            .map_err(|fault| KeyAuthorizationsFault::Elements(name_space.clone(), fault))?;
        data_elements.push(DataElements {
            name_space,
            identifiers,
        });
    }
    Distinct::new(data_elements).map_err(|_| KeyAuthorizationsFault::Cbor(CborError::RepeatedKey))
}

/// A non-empty array of text strings, each once, each read by `name`.
fn names_once<T>(item: &Value, name: fn(&str) -> T) -> Result<Vec<T>, NamesFault> {
    let names = non_empty_array(Some(item)).map_err(NamesFault::Member)?;
    let mut seen = FxHashSet::default();
    let mut read = Vec::with_capacity(names.len());
    for text in names {
        let text = text.as_text().ok_or(NamesFault::NotText)?;
        if !seen.insert(text) {
            return Err(NamesFault::Repeated(text.to_owned()));
        }
        read.push(name(text));
    }
    Ok(read)
}
