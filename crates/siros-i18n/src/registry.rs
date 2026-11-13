//! The formatters each argument type takes: by name in a call, and one by default where the
//! wording names none.

use std::any::TypeId;

use siros_explain::Arg;

use crate::error::RegisterError;
use crate::format::Function;

/// The functions each argument type takes, which a [`Context`](crate::Context) takes through
/// [`Context::formatters`](crate::Context::formatters): a call may name a function the
/// argument's type takes, and a placeholder `{$x}`, a declaration `.input {$x}` and a selector
/// `.match $x` that name none take its default. Every type takes `:string`, which writes its
/// value's `Display`, and takes it by default where it registers no other.
#[derive(Debug, Clone, Default)]
pub struct Formatters(Vec<Taken>);

/// One type's functions: its id, by which the formatters sort, its name, for errors, the
/// functions a call may name, and its default.
#[derive(Debug, Clone)]
struct Taken {
    id: TypeId,
    of: &'static str,
    named: Vec<Function>,
    default: Option<Function>,
}

impl Formatters {
    /// No type taking a function but `:string`.
    #[must_use]
    pub fn new() -> Self {
        <Self as Default>::default()
    }

    /// The formatters, with an argument of the type `T` taking the function `name`, without
    /// its colon, where a call names it.
    ///
    /// # Errors
    ///
    /// [`RegisterError::Function`] for a function the build lacks, and
    /// [`RegisterError::Repeated`] for a function `T` takes already.
    pub fn formatter<T: Arg>(self, name: &str) -> Result<Self, RegisterError> {
        self.register::<T>(name, false)
    }

    /// The formatters, with an argument of the type `T` taking the function `name` where a call
    /// names it and where the wording names none.
    ///
    /// # Errors
    ///
    /// The [`RegisterError`] of [`Formatters::formatter`], and [`RegisterError::Default`] for a
    /// second default of `T`.
    pub fn default_formatter<T: Arg>(self, name: &str) -> Result<Self, RegisterError> {
        self.register::<T>(name, true)
    }

    /// The formatters, with `T` taking `name`, by default when `default`.
    fn register<T: Arg>(mut self, name: &str, default: bool) -> Result<Self, RegisterError> {
        let of = std::any::type_name::<T>();
        let function = Function::named(name).ok_or_else(|| RegisterError::Function {
            name: name.to_owned(),
        })?;
        let id = TypeId::of::<T>();
        match self.0.iter_mut().find(|taken| taken.id == id) {
            Some(taken) => taken.take(function, name, default)?,
            None => {
                let mut taken = Taken {
                    id,
                    of,
                    named: Vec::new(),
                    default: None,
                };
                taken.take(function, name, default)?;
                self.0.push(taken);
                self.0.sort_unstable_by_key(|taken| taken.id);
            }
        }
        Ok(self)
    }

    /// The functions of the type `of`.
    fn of(&self, of: TypeId) -> Option<&Taken> {
        self.0
            .binary_search_by_key(&of, |taken| taken.id)
            .ok()
            .and_then(|at| self.0.get(at))
    }

    /// The function a value of the type `of` takes where the wording names none.
    pub(crate) fn default(&self, of: TypeId) -> Function {
        self.of(of)
            .and_then(|taken| taken.default)
            .unwrap_or(Function::String)
    }

    /// Whether a value of the type `of` takes `function`.
    pub(crate) fn takes(&self, of: TypeId, function: Function) -> bool {
        function == Function::String
            || self
                .of(of)
                .is_some_and(|taken| taken.named.contains(&function))
    }

    /// Every function some type takes, each with the name of one type that takes it.
    #[cfg(feature = "check")]
    pub(crate) fn functions(&self) -> impl Iterator<Item = (Function, &'static str)> + '_ {
        self.0
            .iter()
            .flat_map(|taken| taken.named.iter().map(|function| (*function, taken.of)))
    }
}

impl Taken {
    /// The type takes `function`, named `name`, by default when `default`.
    ///
    /// # Errors
    ///
    /// [`RegisterError::Repeated`] for a function the type takes already, and
    /// [`RegisterError::Default`] for a second default.
    fn take(&mut self, function: Function, name: &str, default: bool) -> Result<(), RegisterError> {
        if self.named.contains(&function) {
            return Err(RegisterError::Repeated {
                of: self.of,
                name: name.to_owned(),
            });
        }
        if default {
            if self.default.is_some() {
                return Err(RegisterError::Default { of: self.of });
            }
            self.default = Some(function);
        }
        self.named.push(function);
        Ok(())
    }
}
