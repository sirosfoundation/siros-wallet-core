//! The elements the device key may sign in `DeviceSigned` (ISO/IEC 18013-5, 9.1.2.4).

use rustc_hash::{FxHashMap, FxHashSet};
use siros_codec::cbor::Item;

use crate::error::{KeyAuthorizationsFault, NamesFault};
use crate::mso::{non_empty_array, non_empty_map};
use crate::names::{ElementIdentifier, NameSpace};

/// The elements the device key may sign: every element of the namespaces of `nameSpaces`, and
/// the elements `dataElements` names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyAuthorizations {
    name_spaces: FxHashSet<NameSpace>,
    data_elements: FxHashMap<NameSpace, FxHashSet<ElementIdentifier>>,
}

impl KeyAuthorizations {
    /// `KeyAuthorizations = {? "nameSpaces": [+ NameSpace], ? "dataElements": {+ NameSpace =>
    /// [+ DataElementIdentifier]}}`. A namespace authorized whole is not also in `dataElements`.
    pub(crate) fn read(item: Option<&Item<'_>>) -> Result<Self, KeyAuthorizationsFault> {
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
            None => FxHashSet::default(),
        };
        let data_elements = match item.get("dataElements") {
            Some(elements) => read_data_elements(elements, &name_spaces)?,
            None => FxHashMap::default(),
        };
        Ok(Self {
            name_spaces,
            data_elements,
        })
    }

    /// Whether the device key may sign `identifier` of `name_space`. [`Mdoc::disclose`]
    /// refuses each `DeviceSigned` element this does not authorize.
    ///
    /// [`Mdoc::disclose`]: crate::Mdoc::disclose
    #[must_use]
    pub fn authorizes(&self, name_space: &NameSpace, identifier: &ElementIdentifier) -> bool {
        self.name_spaces.contains(name_space)
            || self
                .data_elements
                .get(name_space)
                .is_some_and(|identifiers| identifiers.contains(identifier))
    }
}

/// `dataElements`, none of whose namespaces `name_spaces` authorizes whole.
fn read_data_elements(
    elements: &Item<'_>,
    name_spaces: &FxHashSet<NameSpace>,
) -> Result<FxHashMap<NameSpace, FxHashSet<ElementIdentifier>>, KeyAuthorizationsFault> {
    let entries = non_empty_map(Some(elements)).map_err(KeyAuthorizationsFault::DataElements)?;
    let mut data_elements = FxHashMap::default();
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
        if data_elements.contains_key(&name_space) {
            return Err(KeyAuthorizationsFault::RepeatedNameSpace(name_space));
        }
        data_elements.insert(name_space, identifiers);
    }
    Ok(data_elements)
}

/// A non-empty array of text strings, each once, each read by `name`.
fn names_once<T: Eq + std::hash::Hash>(
    item: &Item<'_>,
    name: fn(&str) -> T,
) -> Result<FxHashSet<T>, NamesFault> {
    let names = non_empty_array(Some(item)).map_err(NamesFault::Member)?;
    let mut set = FxHashSet::default();
    for text in names {
        let text = text.as_text().ok_or(NamesFault::NotText)?;
        if !set.insert(name(text)) {
            return Err(NamesFault::Repeated(text.to_owned()));
        }
    }
    Ok(set)
}
