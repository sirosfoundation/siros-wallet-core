//! The build's functions, one family per feature: `:string` always, `:number` and `:integer`
//! (`number`), `:currency` (`currency`), and `:siros:date`, `:siros:time` and `:siros:datetime`
//! (`date`). A family with options parses its `[formats.<format>]` section. The load checks each
//! [`Chain`] for the use a placeholder, a selector or an option makes of it; a resolution reads
//! the sections and formats, selects or takes the value.

use std::borrow::Cow;

use crate::chain::{Call, Chain, Failure, Refused, Texts};
use crate::error::Refusal;
pub(crate) use crate::formats::Formats;
#[cfg(any(feature = "number", feature = "currency", feature = "date"))]
pub(crate) use crate::formats::Options;
use crate::formats::Section;
use crate::scope::Scope;

/// A text's directionality: a message's, by its module's `@dir`, and a formatted value's, which
/// MF2's Default Bidi Strategy isolates it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    /// Left to right.
    Ltr,
    /// Right to left.
    Rtl,
    /// Not known.
    Unknown,
}

/// A function the build compiles in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Function {
    String,
    #[cfg(feature = "number")]
    Number,
    #[cfg(feature = "number")]
    Integer,
    #[cfg(feature = "currency")]
    Currency,
    #[cfg(feature = "date")]
    Date,
    #[cfg(feature = "date")]
    Time,
    #[cfg(feature = "date")]
    DateTime,
}

impl Function {
    /// Every function of the build.
    const ALL: &'static [Self] = &[
        Self::String,
        #[cfg(feature = "number")]
        Self::Number,
        #[cfg(feature = "number")]
        Self::Integer,
        #[cfg(feature = "currency")]
        Self::Currency,
        #[cfg(feature = "date")]
        Self::Date,
        #[cfg(feature = "date")]
        Self::Time,
        #[cfg(feature = "date")]
        Self::DateTime,
    ];

    /// The function of this name, without its colon; `None` for a function the build lacks.
    pub(crate) fn named(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|function| function.name() == name)
    }

    /// Its name, without its colon.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            #[cfg(feature = "number")]
            Self::Number => "number",
            #[cfg(feature = "number")]
            Self::Integer => "integer",
            #[cfg(feature = "currency")]
            Self::Currency => "currency",
            #[cfg(feature = "date")]
            Self::Date => "siros:date",
            #[cfg(feature = "date")]
            Self::Time => "siros:time",
            #[cfg(feature = "date")]
            Self::DateTime => "siros:datetime",
        }
    }

    /// Its call without options: the call of a placeholder or a selector whose wording names no
    /// function, over an argument whose type takes it by default.
    pub(crate) fn bare(self) -> &'static Call {
        macro_rules! bare {
            ($function:expr) => {{
                static CALL: Call = Call::new($function, Vec::new());
                &CALL
            }};
        }
        match self {
            Self::String => bare!(Function::String),
            #[cfg(feature = "number")]
            Self::Number => bare!(Function::Number),
            #[cfg(feature = "number")]
            Self::Integer => bare!(Function::Integer),
            #[cfg(feature = "currency")]
            Self::Currency => bare!(Function::Currency),
            #[cfg(feature = "date")]
            Self::Date => bare!(Function::Date),
            #[cfg(feature = "date")]
            Self::Time => bare!(Function::Time),
            #[cfg(feature = "date")]
            Self::DateTime => bare!(Function::DateTime),
        }
    }

    /// The family whose check and resolution it shares.
    const fn family(self) -> Family {
        match self {
            Self::String => Family::String,
            #[cfg(feature = "number")]
            Self::Number | Self::Integer => Family::Numeric,
            #[cfg(feature = "currency")]
            Self::Currency => Family::Numeric,
            #[cfg(feature = "date")]
            Self::Date | Self::Time | Self::DateTime => Family::Date,
        }
    }

    /// The section that defines its options; `None` for a function that takes none.
    pub(crate) const fn section(self) -> Option<Section> {
        match self {
            Self::String => None,
            #[cfg(feature = "number")]
            Self::Number | Self::Integer => Some(Section::Number),
            #[cfg(feature = "currency")]
            Self::Currency => Some(Section::Currency),
            #[cfg(feature = "date")]
            Self::Date | Self::Time | Self::DateTime => Some(Section::Date),
        }
    }
}

/// The functions that share a check and a resolution.
enum Family {
    String,
    #[cfg(any(feature = "number", feature = "currency"))]
    Numeric,
    #[cfg(feature = "date")]
    Date,
}

/// The numeric chain's language: the section of the function that formats its value.
///
/// # Errors
///
/// [`Refused::Undefined`] for a section no module defined, and [`Refusal::Operand`] for a chain
/// with a call of another family.
#[cfg(any(feature = "number", feature = "currency"))]
fn language<'f>(
    chain: &Chain<'_>,
    formats: &'f Formats,
) -> Result<crate::numeric::Language<'f>, Refused> {
    use crate::numeric::options::Function as Numeric;
    match crate::numeric::formatter(chain).ok_or(Refusal::Operand)? {
        #[cfg(feature = "currency")]
        Numeric::Currency => Ok(crate::numeric::Language::Currency(
            formats.currency().ok_or(Refused::Undefined)?,
        )),
        #[cfg(feature = "number")]
        Numeric::Number | Numeric::Integer => Ok(crate::numeric::Language::Plain(
            formats.number().ok_or(Refused::Undefined)?,
        )),
        #[cfg(not(all(feature = "number", feature = "currency")))]
        _ => Err(Refusal::Operand.into()),
    }
}

/// The numeric chain's language at resolution.
///
/// # Errors
///
/// [`Failure::Operand`] for a chain no section of the context formats.
#[cfg(any(feature = "number", feature = "currency"))]
fn formatting<'f>(
    chain: &Chain<'_>,
    formats: &'f Formats,
) -> Result<crate::numeric::Language<'f>, Failure> {
    language(chain, formats).map_err(|_| Failure::Operand)
}

/// Checks the chain for its use at a placeholder or as an option's value, against the sections
/// of the modules loaded so far.
///
/// # Errors
///
/// [`Refused`] for a section no module defined, or a call the function refuses.
pub(crate) fn check(
    chain: &Chain<'_>,
    #[cfg_attr(
        not(any(feature = "number", feature = "currency", feature = "date")),
        expect(unused_variables, reason = "only the format functions read a section")
    )]
    formats: &Formats,
) -> Result<(), Refused> {
    match chain.outer.function.family() {
        Family::String => crate::string::check(chain),
        #[cfg(any(feature = "number", feature = "currency"))]
        Family::Numeric => crate::numeric::check(chain, language(chain, formats)?),
        #[cfg(feature = "date")]
        Family::Date => {
            if formats.date().is_none() {
                return Err(Refused::Undefined);
            }
            Ok(crate::date::check(chain)?)
        }
    }
}

/// How a selector's function selects.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Selecting {
    /// `:string`: the key equal to the operand's text.
    Text,
    /// A numeric function: by its `select`.
    #[cfg(any(feature = "number", feature = "currency"))]
    Number(crate::numeric::Selection),
}

impl Selecting {
    /// How the chain selects, checked for its use as a selector against the sections of the
    /// modules loaded so far.
    ///
    /// # Errors
    ///
    /// [`Refused`] for a section no module defined, or a call the function refuses: a function
    /// that does not select refuses with [`Refusal::Selector`].
    pub(crate) fn of(
        chain: &Chain<'_>,
        #[cfg_attr(
            not(any(feature = "number", feature = "currency")),
            expect(unused_variables, reason = "only the numeric functions read a section")
        )]
        formats: &Formats,
    ) -> Result<Self, Refused> {
        match chain.outer.function.family() {
            Family::String => crate::string::check(chain).map(|()| Self::Text),
            #[cfg(any(feature = "number", feature = "currency"))]
            Family::Numeric => {
                crate::numeric::selection(chain, language(chain, formats)?).map(Self::Number)
            }
            #[cfg(feature = "date")]
            Family::Date => Err(Refusal::Selector.into()),
        }
    }

    /// Refuses a variant key the selection does not read.
    ///
    /// # Errors
    ///
    /// [`Refusal::Key`] for such a key.
    pub(crate) fn reads(
        self,
        #[cfg_attr(
            not(any(feature = "number", feature = "currency")),
            expect(unused_variables, reason = "only the numeric selection refuses a key")
        )]
        key: &str,
    ) -> Result<(), Refusal> {
        match self {
            #[cfg(any(feature = "number", feature = "currency"))]
            Self::Number(_) => crate::numeric::key(key),
            _ => Ok(()),
        }
    }

    /// What the chain's value selects with, its options resolved to `texts`.
    ///
    /// # Errors
    ///
    /// [`Failure`] as [`format`].
    pub(crate) fn selected<'s>(
        self,
        chain: &Chain<'s>,
        #[cfg_attr(
            not(any(feature = "number", feature = "currency")),
            expect(unused_variables, reason = "`:string` reads no option")
        )]
        texts: &Texts<'_>,
        scope: &Scope<'s>,
    ) -> Result<Selected<'s>, Failure> {
        match self {
            Self::Text => crate::string::value(chain, scope).map(Selected::Text),
            #[cfg(any(feature = "number", feature = "currency"))]
            Self::Number(selection) => {
                let language = formatting(chain, scope.formats)?;
                crate::numeric::selected(chain, texts, scope, language, selection)
                    .map(Selected::Number)
            }
        }
    }
}

/// What a selector's value selects with.
#[derive(Debug)]
pub(crate) enum Selected<'s> {
    /// The text a key equals.
    Text(&'s str),
    /// A number's exact key and plural category.
    #[cfg(any(feature = "number", feature = "currency"))]
    Number(crate::numeric::Selected),
}

impl Selected<'_> {
    /// The rank of `key` among the keys the value matches, from 0 for the best; `None` for a key
    /// it does not match.
    pub(crate) fn rank(&self, key: &str) -> Option<usize> {
        match self {
            Self::Text(text) => (*text == key).then_some(0),
            #[cfg(any(feature = "number", feature = "currency"))]
            Self::Number(number) => number.rank(key),
        }
    }
}

/// The chain's value as an option's value: the operand's text for `:string` and the date
/// functions, the number for the numeric functions.
///
/// # Errors
///
/// [`Failure`] as [`format`].
pub(crate) fn value<'m>(chain: &Chain<'m>, scope: &Scope<'m>) -> Result<Cow<'m, str>, Failure> {
    #[cfg_attr(
        not(any(feature = "number", feature = "currency", feature = "date")),
        expect(unused_variables, reason = "`:string` reads no option")
    )]
    let texts = chain.texts(scope)?;
    match chain.outer.function.family() {
        Family::String => crate::string::value(chain, scope).map(Cow::Borrowed),
        #[cfg(any(feature = "number", feature = "currency"))]
        Family::Numeric => {
            let language = formatting(chain, scope.formats)?;
            crate::numeric::value(chain, &texts, scope, language).map(Cow::Owned)
        }
        #[cfg(feature = "date")]
        Family::Date => crate::date::value(chain, &texts, scope).map(Cow::Borrowed),
    }
}

/// The chain's value formatted with its resolved options `texts`, and the formatted text's
/// direction.
///
/// # Errors
///
/// [`Failure`] for an operand or an option text the function refuses, a chain no section of the
/// context formats, or an argument the message does not give.
pub(crate) fn format(
    chain: &Chain<'_>,
    #[cfg_attr(
        not(any(feature = "number", feature = "currency", feature = "date")),
        expect(unused_variables, reason = "`:string` reads no option")
    )]
    texts: &Texts<'_>,
    scope: &Scope<'_>,
) -> Result<(String, Direction), Failure> {
    match chain.outer.function.family() {
        Family::String => {
            crate::string::value(chain, scope).map(|text| (text.to_owned(), Direction::Unknown))
        }
        #[cfg(any(feature = "number", feature = "currency"))]
        Family::Numeric => {
            let language = formatting(chain, scope.formats)?;
            let text = crate::numeric::format(chain, texts, scope, language)?;
            Ok((text, language.direction()))
        }
        #[cfg(feature = "date")]
        Family::Date => {
            let section = scope.formats.date().ok_or(Failure::Operand)?;
            let text = crate::date::format(chain, texts, scope, section)?;
            Ok((text, section.direction()))
        }
    }
}
