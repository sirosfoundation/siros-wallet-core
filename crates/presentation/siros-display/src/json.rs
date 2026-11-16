//! Reading members of metadata objects.

use rustc_hash::FxHashSet;
use serde_json::{Map, Value};

use crate::colour::Colour;
use crate::error::{ColourFault, DisplayError, EntryFault};
use crate::locale::Locale;
use crate::text::{LabelText, TextError};

/// How many entries an array member holds.
#[derive(Clone, Copy)]
pub(crate) enum Entries {
    /// At least one.
    AtLeastOne,
    /// Any number, none included.
    Any,
}

/// The object `value`.
pub(crate) fn object(value: &Value) -> Result<&Map<String, Value>, DisplayError> {
    value.as_object().ok_or(DisplayError::NotObject)
}

/// The string member `name`; `None` when absent.
pub(crate) fn string<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    malformed: DisplayError,
) -> Result<Option<&'a str>, DisplayError> {
    match object.get(name) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(malformed),
    }
}

/// The OPTIONAL string member `name` as a label; `None` when absent or blank, which the host's
/// wording or the claim key then stands for.
pub(crate) fn optional_label(
    object: &Map<String, Value>,
    name: &str,
    malformed: DisplayError,
) -> Result<Option<LabelText>, DisplayError> {
    match label(object, name, malformed) {
        Err(DisplayError::Text(TextError::Empty)) => Ok(None),
        read => read,
    }
}

/// The string member `name` as a label; `None` when absent.
pub(crate) fn label(
    object: &Map<String, Value>,
    name: &str,
    malformed: DisplayError,
) -> Result<Option<LabelText>, DisplayError> {
    string(object, name, malformed)?
        .map(|text| LabelText::new(text).map_err(DisplayError::Text))
        .transpose()
}

/// The language tag `locale`; `None` when absent.
pub(crate) fn locale(
    object: &Map<String, Value>,
    malformed: DisplayError,
) -> Result<Option<Locale>, DisplayError> {
    string(object, "locale", malformed)?
        .map(|tag| Locale::parse(tag).map_err(DisplayError::Locale))
        .transpose()
}

/// The colour member `name`; `None` when absent.
pub(crate) fn colour(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<Colour>, DisplayError> {
    string(object, name, DisplayError::Colour(ColourFault::NotString))?
        .map(Colour::parse)
        .transpose()
}

/// The array member `name` of `entries`; `None` when absent.
pub(crate) fn array<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    entries: Entries,
    malformed: fn(EntryFault) -> DisplayError,
) -> Result<Option<&'a [Value]>, DisplayError> {
    match (object.get(name), entries) {
        (None, _) => Ok(None),
        (Some(Value::Array(items)), Entries::AtLeastOne) if items.is_empty() => {
            Err(malformed(EntryFault::NotArray))
        }
        (Some(Value::Array(items)), _) => Ok(Some(items)),
        (Some(_), _) => Err(malformed(EntryFault::NotArray)),
    }
}

/// The entry `value` of an array whose faults `malformed` reports: a JSON object.
pub(crate) fn entry(
    value: &Value,
    malformed: fn(EntryFault) -> DisplayError,
) -> Result<&Map<String, Value>, DisplayError> {
    value
        .as_object()
        .ok_or(malformed(EntryFault::EntryNotObject))
}

/// Each entry has a different locale, or none (OpenID4VCI 1.0, Section 12.2.4; SD-JWT VC,
/// Sections 5.5 and 5.6.2).
pub(crate) fn distinct_locales<'a>(
    locales: impl Iterator<Item = Option<&'a Locale>>,
) -> Result<(), DisplayError> {
    let mut seen = FxHashSet::default();
    if locales.flatten().all(|locale| seen.insert(locale)) {
        Ok(())
    } else {
        Err(DisplayError::DisplayLocaleRepeated)
    }
}
