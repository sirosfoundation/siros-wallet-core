//! Localised arrays: a claim's `display` and each `ui_labels` element (PaSO Proof Metadata,
//! Sections 3.1 to 3.3), each read entry by entry.

use rustc_hash::FxHashSet;
use siros_codec::json::Json;
use siros_codec::member::ArrayIndex;
use siros_display::{lookup, Locale, Localized};

use super::error::{DefinitionMember, EntryFault, LabelsFault};
use crate::json::{self, Fields};

/// An array of localised entries: no two with the same locale, and at most one without a locale,
/// the default entry (Section 3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Localizations<T>(Vec<T>);

impl<T: Localized> Localizations<T> {
    /// The array `value`, each entry read by `entry`, which passes over an entry the locale
    /// function excludes by giving `None`.
    pub(crate) fn parse(
        value: Json,
        entry: impl Fn(Fields) -> Result<Option<T>, EntryFault>,
    ) -> Result<Self, LabelsFault> {
        let items = json::array(value).map_err(|_| LabelsFault::NotArray)?;
        let entries: Vec<T> = items
            .into_iter()
            .enumerate()
            .map(|(at, item)| {
                let fault = |fault| LabelsFault::Entry(ArrayIndex::new(at), fault);
                let fields = json::object(item).map_err(|_| fault(EntryFault::NotObject))?;
                entry(fields).map_err(fault)
            })
            .filter_map(Result::transpose)
            .collect::<Result<_, _>>()?;
        let mut seen = FxHashSet::default();
        let mut defaults = 0usize;
        for item in &entries {
            match item.locale() {
                Some(locale) if !seen.insert(locale) => {
                    return Err(LabelsFault::LocaleRepeated(locale.clone()))
                }
                Some(_) => {}
                None if defaults > 0 => return Err(LabelsFault::DefaultRepeated),
                None => defaults += 1,
            }
        }
        Ok(Self(entries))
    }

    /// The array of the one entry `entry`.
    pub(crate) fn single(entry: T) -> Self {
        Self(vec![entry])
    }

    /// The entries, in the metadata's order.
    #[must_use]
    pub fn entries(&self) -> &[T] {
        &self.0
    }

    /// The entry the locale function takes for `language` (PaSO View, Section 4).
    pub(crate) fn lookup(&self, language: &Locale) -> Option<&T> {
        lookup(language, &self.0)
    }
}

/// The optional `locale` of an entry: a language tag (RFC 5646).
pub(crate) fn locale(fields: &mut Fields) -> Result<Option<Locale>, EntryFault> {
    fields
        .optional(DefinitionMember::Locale.as_str(), json::text)
        .map_err(|fault| EntryFault::Member(DefinitionMember::Locale, fault))?
        .map(|tag| Locale::parse(&tag).map_err(EntryFault::Locale))
        .transpose()
}

/// The required string member `member` of an entry.
pub(crate) fn required_text(
    fields: &mut Fields,
    member: DefinitionMember,
) -> Result<String, EntryFault> {
    fields
        .require(member.as_str())
        .and_then(json::text)
        .map_err(|fault| EntryFault::Member(member, fault))
}

/// The optional string member `member` of an entry.
pub(crate) fn optional_text(
    fields: &mut Fields,
    member: DefinitionMember,
) -> Result<Option<String>, EntryFault> {
    fields
        .optional(member.as_str(), json::text)
        .map_err(|fault| EntryFault::Member(member, fault))
}
