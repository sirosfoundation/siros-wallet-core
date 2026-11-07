//! A type's metadata as the wallet's defined module: the wallet converts it at registration as it
//! does PaSO's, under TS12's label limits.

use siros_explain::Explain;
use siros_i18n::{DefinedForm, LocaleTag, MainLocale};
use siros_paso::render::Registered;

use crate::LIMITS;
use crate::document::BuiltInEntry;
use crate::translate::{Ts12Unsupported, paso_metadata};

/// Why a type's metadata converts to no module.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "ts12.convert")]
pub enum ConvertError {
    /// The metadata is unsupported.
    #[error(transparent)]
    Unsupported(#[from] Ts12Unsupported),
    /// siros-paso's engine refuses the translation.
    #[error(transparent)]
    Engine(#[from] siros_paso::view::ConvertError),
}

/// The type's defined module for the End-User's priority list, `LanguagePolicy::Understood`: the
/// wallet shows it in the language View §4 selects.
///
/// # Errors
///
/// [`ConvertError`]: the metadata is unsupported, or the engine refuses it.
pub fn convert(
    entry: &BuiltInEntry<'_>,
    main: &[MainLocale],
    priority: &[LocaleTag],
) -> Result<DefinedForm, ConvertError> {
    let metadata = paso_metadata(entry)?;
    let registered = Registered::of(entry.kind().paso_type(), &metadata);
    Ok(siros_paso::view::convert(
        &registered,
        LIMITS,
        main,
        priority,
    )?)
}
