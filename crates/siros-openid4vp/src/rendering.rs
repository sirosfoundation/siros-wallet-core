//! What a presentation's texts render from: the package the app built from its modules, the
//! build's format modules, and the app's modules beside the defined ones. Each consent entry's
//! renderer shows the module its profile selected a locale for in that locale, and every other
//! module in the language `Screen::locale` decides over `Env`'s lists (section 4.14 of the
//! design); the record commits to the renderer's inputs.

use std::borrow::Cow;

use siros_explain::{Explain, ModuleId};
use siros_i18n::{Formats, ModuleName, NoLanguage, Package, PackageError, Renderer, Screen};

use crate::plugins::{Exclusion, Fault};
use crate::rows::{Env, Selected};
use crate::{FAULT, detail};

/// The package a presentation's texts render from, the build's render halves, and the modules
/// every entry draws from: the app's main module and its crate modules.
#[derive(Clone, Copy)]
pub struct Rendering<'p> {
    package: Package<'p>,
    formats: &'p Formats,
    modules: &'p [ModuleId],
}

impl<'p> Rendering<'p> {
    /// The rendering of `package` through `formats`, every entry drawing from `modules`.
    #[must_use]
    pub const fn new(package: Package<'p>, formats: &'p Formats, modules: &'p [ModuleId]) -> Self {
        Self {
            package,
            formats,
            modules,
        }
    }

    /// An entry's renderer: the app's modules and the module its profile selected a locale for,
    /// that module in its locale and the others in the language `Screen::locale` decides over
    /// `env`'s priority list headed by that locale, `env`'s fallback list and the modules'
    /// policies; with `env`'s rendering options. The inner error excludes the entry.
    ///
    /// # Errors
    ///
    /// A [`Fault`] when the package refuses the screen of the app's modules (a module it does
    /// not hold, another renderer's version, an entry that fails its root) or a module calls a
    /// format the build does not register.
    pub fn renderer(
        &self,
        selected: Option<&Selected>,
        env: &Env,
    ) -> Result<Result<Renderer<'p>, Unrendered>, Fault> {
        let mut modules = self.modules.to_vec();
        if let Some(selected) = selected
            && !modules.contains(&selected.module())
        {
            modules.push(selected.module());
        }
        let refused = |e| Fault::caused(FAULT, detail!("the package refuses the screen"), e);
        let mut screen = match Screen::new(&self.package, modules) {
            Ok(screen) => screen,
            Err(PackageError::Module(module))
                if selected.is_some_and(|selected| selected.module() == module.id()) =>
            {
                return Ok(Err(Unrendered::Module(module)));
            }
            Err(e) => return Err(refused(e)),
        };
        if let Some(selected) = selected {
            screen = screen.selecting(selected.clone()).map_err(refused)?;
        }
        let located = match screen.locale(env.priority(), env.fallback()) {
            Ok(located) => located,
            Err(none) => return Ok(Err(Unrendered::Language(none))),
        };
        located
            .renderer(self.formats, env.options())
            .map(Ok)
            .map_err(|e| Fault::caused(FAULT, detail!("the screen's renderer"), e))
    }
}

/// Why an entry's texts cannot render, which excludes it.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.rendering")]
pub enum Unrendered {
    /// No language serves the entry's modules: a module requires one the End-User understands,
    /// the fallback list serves none, or the module a profile selected a locale for holds no
    /// entry of it.
    #[error(transparent)]
    Language(#[from] NoLanguage),
    /// The package holds no module whose locale the profile selected: metadata the package was
    /// built without, such as metadata that arrives with the request.
    #[error("the package holds no module {0}, whose locale the profile selected")]
    Module(#[explain(name = "module")] ModuleName),
}

impl Exclusion for Unrendered {
    fn clause(&self) -> Cow<'static, str> {
        Cow::Borrowed("one language per presentation")
    }
}
