//! The formatters each argument type takes: by name in a call, and one by default where the
//! wording names none. Every type takes `:string`, its `Display`, by default where it registers
//! no other default.

use std::any::TypeId;

use rustc_hash::FxHashMap;

use crate::error::RegisterError;
use crate::format::Function;

/// The formatters of the argument types a context registers.
#[derive(Debug, Clone, Default)]
pub(crate) struct Registry(FxHashMap<TypeId, Formatters>);

/// One type's formatters: its name, for errors, the functions a call may name, and its default.
#[derive(Debug, Clone)]
struct Formatters {
    of: &'static str,
    named: Vec<Function>,
    default: Option<Function>,
}

impl Registry {
    /// Values of the type `of`, named `type_name`, take the function `name`, by default when
    /// `default`.
    ///
    /// # Errors
    ///
    /// [`RegisterError::Function`] for a function the build lacks, [`RegisterError::Repeated`]
    /// for a function the type takes already, and [`RegisterError::Default`] for a second
    /// default.
    pub(crate) fn register(
        &mut self,
        of: TypeId,
        type_name: &'static str,
        name: &str,
        default: bool,
    ) -> Result<(), RegisterError> {
        let function = Function::named(name).ok_or_else(|| RegisterError::Function {
            name: name.to_owned(),
        })?;
        let formatters = self.0.entry(of).or_insert_with(|| Formatters {
            of: type_name,
            named: Vec::new(),
            default: None,
        });
        if formatters.named.contains(&function) {
            return Err(RegisterError::Repeated {
                of: type_name,
                name: name.to_owned(),
            });
        }
        if default {
            if formatters.default.is_some() {
                return Err(RegisterError::Default { of: type_name });
            }
            formatters.default = Some(function);
        }
        formatters.named.push(function);
        Ok(())
    }

    /// The function a value of the type `of` takes where the wording names none.
    pub(crate) fn default(&self, of: TypeId) -> Function {
        self.0
            .get(&of)
            .and_then(|formatters| formatters.default)
            .unwrap_or(Function::String)
    }

    /// Whether a value of the type `of` takes `function`.
    pub(crate) fn takes(&self, of: TypeId, function: Function) -> bool {
        function == Function::String
            || self
                .0
                .get(&of)
                .is_some_and(|formatters| formatters.named.contains(&function))
    }

    /// Every function some type takes, each with the name of one type that takes it.
    #[cfg(feature = "check")]
    pub(crate) fn functions(&self) -> impl Iterator<Item = (Function, &'static str)> + '_ {
        self.0.values().flat_map(|formatters| {
            formatters
                .named
                .iter()
                .map(|function| (*function, formatters.of))
        })
    }
}
