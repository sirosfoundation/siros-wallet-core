//! A type's metadata as the wallet's defined module: the wallet converts it at registration as it
//! does PaSO's, under TS12's label limits.

use siros_i18n::{DefinedForm, LocaleTag, MainLocale};
use siros_openid4vp::json::Node;
use siros_paso::render::Registered;
use siros_paso::view::ConvertError;

use crate::LIMITS;
use crate::document::BuiltInEntry;
use crate::translate::paso_metadata;

/// The type's defined module for the End-User's priority list, `LanguagePolicy::Understood`: the
/// wallet shows it in the language View §4 selects.
///
/// # Errors
///
/// [`ConvertError`]: the engine refuses the translation.
pub fn convert(
    entry: &BuiltInEntry<'_>,
    main: &[MainLocale],
    priority: &[LocaleTag],
) -> Result<DefinedForm, ConvertError> {
    let metadata = Node::Object(paso_metadata(entry));
    let registered = Registered::of(entry.kind().paso_type(), &metadata);
    siros_paso::view::convert(&registered, LIMITS, main, priority)
}
