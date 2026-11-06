//! The registration writer's part inside the workspace (section 4.14 of the design, "DC API
//! precomputation"): the package the registration carries for the matcher. It holds the
//! modules' compiled messages, every card's texts precomputed in each of the package's locales
//! whose modules serve them (the End-User's priority list with each tag's RFC 4647 truncations
//! and the app's fallback list, [`RegistrationBuilder::new`]), and what it was built from: the
//! lists, the rendering options, each credential with its candidate languages, each transaction
//! type with its module. The registration's bytes are siros-dc-matcher's.

use siros_explain::{Explain, ModuleId};
use siros_i18n::{
    BuiltPackage, DefinedForm, Formats, Module, PackageError, RegistrationBuilder, RenderError,
};
use siros_openid4vp::consent::Card;
use siros_openid4vp::rows::Env;

use crate::emit::held;

/// Why a registration's package is not written.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "credman.register")]
pub enum RegisterError {
    /// The builder refuses a module, a credential or a transaction type.
    #[error(transparent)]
    Package(#[from] PackageError),
    /// A text does not render.
    #[error(transparent)]
    Render(#[from] RenderError),
}

/// What a registration serves.
#[derive(Debug, Clone, Copy)]
pub struct Registration<'r> {
    /// The app's modules the package holds.
    pub modules: &'r [&'r Module],
    /// The modules every card draws from: the app's main module and its crate modules, as the
    /// matcher's `Rendering` names them.
    pub own: &'r [ModuleId],
    /// Each card a credential shows, by the credential's id; a credential may show several.
    pub credentials: &'r [(&'r str, &'r Card)],
    /// The static entries' cards.
    pub statics: &'r [&'r Card],
    /// Each transaction type, with the defined module its metadata converts to.
    pub transactions: &'r [(&'r str, &'r DefinedForm)],
}

/// The package of a registration under `env`'s lists and options: every key of each module, each
/// credential and transaction type recorded, and every card's texts precomputed.
///
/// # Errors
///
/// [`RegisterError`]: the builder refuses a module, a credential or a transaction type, or a
/// card's text renders in no tag of the lists.
pub fn package(
    registration: &Registration<'_>,
    env: &Env,
    formats: &Formats,
) -> Result<BuiltPackage, RegisterError> {
    let mut builder = RegistrationBuilder::new(
        env.priority().to_vec(),
        env.fallback().to_vec(),
        env.options(),
    )?;
    for module in registration.modules {
        builder.module(module, None)?;
    }
    let mut credentials: Vec<&str> = registration.credentials.iter().map(|(id, _)| *id).collect();
    credentials.sort_unstable();
    credentials.dedup();
    for credential in credentials {
        builder.credential(credential, registration.own)?;
    }
    let mut defined: Vec<&DefinedForm> = Vec::new();
    for (_, form) in registration.transactions {
        if defined.iter().all(|known| known.id() != form.id()) {
            builder.defined(form)?;
            defined.push(form);
        }
    }
    for (kind, form) in registration.transactions {
        builder.transaction(kind, ModuleId::Defined(form.id()))?;
    }
    let mut texts = builder.texts(formats);
    let cards = registration
        .credentials
        .iter()
        .map(|(_, card)| *card)
        .chain(registration.statics.iter().copied());
    for card in cards {
        for text in held(card) {
            texts.precompute(text, env.options())?;
        }
    }
    Ok(texts.finish())
}
