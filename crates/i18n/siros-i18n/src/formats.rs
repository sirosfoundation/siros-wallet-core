//! The format sections of a context: `[formats.number]`, `[formats.currency]` and
//! `[formats.date]`, each parsed by its family when the build compiles the family in.

use crate::error::{FormatRule, LoadError};
use crate::format::{Direction, Function};
use crate::resource::Entry;
use crate::seen::repeated;

/// A `[formats.<format>]` section's format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Section {
    Number,
    Currency,
    Date,
}

impl Section {
    const ALL: [Self; 3] = [Self::Number, Self::Currency, Self::Date];

    fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|section| section.name() == name)
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Number => "number",
            Self::Currency => "currency",
            Self::Date => "date",
        }
    }
}

/// A format section's options, each name once, each one its format takes; and the direction of
/// the module that defines it.
#[cfg(any(feature = "number", feature = "currency", feature = "date"))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Options<'s> {
    entries: &'s [&'s Entry<'s>],
    pub(crate) direction: Direction,
}

#[cfg(any(feature = "number", feature = "currency", feature = "date"))]
impl<'s> Options<'s> {
    /// The option `name`'s text.
    ///
    /// # Errors
    ///
    /// [`FormatRule::Missing`] when the section lacks it.
    pub(crate) fn text(&self, name: &'static str) -> Result<&'s str, FormatRule> {
        self.entries
            .iter()
            .find(|entry| entry.key == name)
            .map(|entry| entry.value.as_ref())
            .ok_or(FormatRule::Missing { option: name })
    }

    /// The option `name`, parsed by `accept`.
    ///
    /// # Errors
    ///
    /// [`FormatRule::Missing`] when the section lacks it, [`FormatRule::Text`] when `accept`
    /// refuses its text.
    pub(crate) fn parse<T>(
        &self,
        name: &'static str,
        accept: impl FnOnce(&'s str) -> Option<T>,
    ) -> Result<T, FormatRule> {
        accept(self.text(name)?).ok_or(FormatRule::Text { option: name })
    }
}

/// The format sections a context defines, each parsed by its family; a section of a format the
/// build lacks is held by name alone.
#[derive(Debug, Clone, Default)]
pub(crate) struct Formats {
    defined: Vec<Section>,
    #[cfg(feature = "number")]
    number: Option<crate::numeric::Plain>,
    #[cfg(feature = "currency")]
    currency: Option<crate::numeric::currency::Parsed>,
    #[cfg(feature = "date")]
    date: Option<crate::date::Parsed>,
}

impl Formats {
    /// Defines the format `format` by `options`, those of a module whose direction is
    /// `direction`.
    ///
    /// # Errors
    ///
    /// [`LoadError::Repeated`] for a format the context holds or an option given twice,
    /// [`LoadError::Format`] for options the format refuses.
    pub(crate) fn define(
        &mut self,
        format: &str,
        options: &[&Entry<'_>],
        #[cfg_attr(
            not(any(feature = "number", feature = "currency", feature = "date")),
            expect(unused_variables, reason = "a build without formats parses no section")
        )]
        direction: Direction,
    ) -> Result<(), LoadError> {
        let refuse = |rule| LoadError::Format {
            format: format.to_owned(),
            rule,
        };
        let Some(named) = Section::named(format) else {
            return Err(refuse(FormatRule::Unknown));
        };
        if self.defined.contains(&named) {
            return Err(LoadError::Repeated {
                id: format!("formats.{format}"),
            });
        }
        if let Some(option) = repeated(options.iter().map(|entry| entry.key.as_ref())) {
            return Err(LoadError::Repeated {
                id: format!("formats.{format}.{option}"),
            });
        }
        #[cfg(any(feature = "number", feature = "currency", feature = "date"))]
        self.parse(
            named,
            Options {
                entries: options,
                direction,
            },
        )
        .map_err(refuse)?;
        self.defined.push(named);
        Ok(())
    }

    /// `[formats.number]`, when a module defined it.
    #[cfg(feature = "number")]
    pub(crate) const fn number(&self) -> Option<&crate::numeric::Plain> {
        self.number.as_ref()
    }

    /// `[formats.currency]`, when a module defined it.
    #[cfg(feature = "currency")]
    pub(crate) const fn currency(&self) -> Option<&crate::numeric::currency::Parsed> {
        self.currency.as_ref()
    }

    /// `[formats.date]`, when a module defined it.
    #[cfg(feature = "date")]
    pub(crate) const fn date(&self) -> Option<&crate::date::Parsed> {
        self.date.as_ref()
    }

    /// Parses a section of a format the build compiles in; a section of another format stays
    /// unparsed.
    #[cfg(any(feature = "number", feature = "currency", feature = "date"))]
    fn parse(&mut self, section: Section, options: Options<'_>) -> Result<(), FormatRule> {
        match section {
            #[cfg(feature = "number")]
            Section::Number => {
                takes(options, &crate::numeric::PLAIN)?;
                self.number = Some(crate::numeric::Plain::parse(options)?);
            }
            #[cfg(feature = "currency")]
            Section::Currency => {
                takes(options, &crate::numeric::currency::OPTIONS)?;
                self.currency = Some(crate::numeric::currency::Parsed::parse(options)?);
            }
            #[cfg(feature = "date")]
            Section::Date => {
                takes(options, &crate::date::OPTIONS)?;
                self.date = Some(crate::date::Parsed::parse(options)?);
            }
            #[cfg(not(all(feature = "number", feature = "currency", feature = "date")))]
            _ => {}
        }
        Ok(())
    }

    /// Whether a module defined the section of `function`'s options; a function that takes none
    /// needs no section.
    pub(crate) fn defines(&self, function: Function) -> bool {
        function
            .section()
            .is_none_or(|section| self.defined.contains(&section))
    }
}

/// Refuses an option the format does not take.
#[cfg(any(feature = "number", feature = "currency", feature = "date"))]
fn takes(options: Options<'_>, names: &[&str]) -> Result<(), FormatRule> {
    match options
        .entries
        .iter()
        .find(|entry| !names.contains(&entry.key.as_ref()))
    {
        Some(entry) => Err(FormatRule::Undefined {
            option: entry.key.to_string(),
        }),
        None => Ok(()),
    }
}
