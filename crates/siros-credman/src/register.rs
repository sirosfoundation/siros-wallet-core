//! The registration writer's part inside the workspace (section 4.14 of the design, "DC API
//! precomputation"): the package the registration carries for the matcher, holding the modules'
//! compiled messages and the texts no request changes precomputed. The registration's bytes are
//! siros-dc-matcher's.

use siros_explain::{Explain, Text};
use siros_i18n::{
    BuiltPackage, Formats, LocaleTag, Module, PackageBuilder, PackageError, RenderError,
};
use siros_openid4vp::consent::Card;
use siros_openid4vp::rows::{RenderOptions, Value};

/// Why a registration's package is not written.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "credman.register")]
pub enum RegisterError {
    /// The builder refuses a module.
    #[error(transparent)]
    Package(#[from] PackageError),
    /// A text does not render.
    #[error(transparent)]
    Render(#[from] RenderError),
}

/// The texts of a card no request changes: its title and subtitle, and each row's label, value
/// and section. A matcher reads them as held.
pub fn held(card: &Card) -> impl Iterator<Item = &Text> {
    std::iter::once(&card.title)
        .chain(&card.subtitle)
        .chain(card.rows.iter().flat_map(|row| {
            std::iter::once(&row.label)
                .chain(row.value.as_ref().and_then(Value::text))
                .chain(&row.section)
        }))
}

/// The package of `modules`, every key of each in every locale one of them supports, with each
/// of `held` precomputed under `options` in each package locale whose modules serve it.
///
/// # Errors
///
/// [`RegisterError`]: the builder refuses a module, or a text renders in no package locale.
pub fn package(
    modules: &[&Module],
    held: &[&Text],
    formats: &Formats,
    options: RenderOptions,
) -> Result<BuiltPackage, RegisterError> {
    let mut locales: Vec<LocaleTag> = modules
        .iter()
        .flat_map(|module| module.locales().cloned())
        .collect();
    locales.sort();
    locales.dedup();
    let mut builder = PackageBuilder::new(locales)?;
    for module in modules {
        builder.module(module, None)?;
    }
    let mut texts = builder.texts(formats);
    for text in held {
        texts.precompute(text, options)?;
    }
    Ok(texts.finish())
}
