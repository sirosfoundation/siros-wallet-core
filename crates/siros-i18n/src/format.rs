//! The build's functions, one family per feature: `:string` always, `:number` and `:integer`
//! (`number`), `:offset` (`offset`), `:currency` and `:percent` (`currency`), `:siros:date`,
//! `:siros:time` and `:siros:datetime` (`date`), and MF2's test functions (`conformance`). A
//! family with options parses its `[formats.<format>]` section. The load checks each
//! [`Chain`] for the use a placeholder, a selector or an option makes of it; a resolution reads
//! the sections and formats, selects or takes the value.

use std::borrow::Cow;

use crate::chain::{Chain, Failure, Refused, Texts, Use};
use crate::error::Refusal;
pub(crate) use crate::formats::Formats;
#[cfg(any(
    feature = "number",
    feature = "currency",
    feature = "offset",
    feature = "date"
))]
pub(crate) use crate::formats::Options;
use crate::formats::Section;
use crate::normal::Hold;
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
    #[cfg(feature = "offset")]
    Offset,
    #[cfg(feature = "currency")]
    Currency,
    #[cfg(feature = "currency")]
    Percent,
    #[cfg(feature = "date")]
    Date,
    #[cfg(feature = "date")]
    Time,
    #[cfg(feature = "date")]
    DateTime,
    /// `:test:function`.
    #[cfg(feature = "conformance")]
    Test,
    #[cfg(feature = "conformance")]
    TestSelect,
    #[cfg(feature = "conformance")]
    TestFormat,
}

impl Function {
    /// Every function of the build.
    const ALL: &'static [Self] = &[
        Self::String,
        #[cfg(feature = "number")]
        Self::Number,
        #[cfg(feature = "number")]
        Self::Integer,
        #[cfg(feature = "offset")]
        Self::Offset,
        #[cfg(feature = "currency")]
        Self::Currency,
        #[cfg(feature = "currency")]
        Self::Percent,
        #[cfg(feature = "date")]
        Self::Date,
        #[cfg(feature = "date")]
        Self::Time,
        #[cfg(feature = "date")]
        Self::DateTime,
        #[cfg(feature = "conformance")]
        Self::Test,
        #[cfg(feature = "conformance")]
        Self::TestSelect,
        #[cfg(feature = "conformance")]
        Self::TestFormat,
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
            #[cfg(feature = "offset")]
            Self::Offset => "offset",
            #[cfg(feature = "currency")]
            Self::Currency => "currency",
            #[cfg(feature = "currency")]
            Self::Percent => "percent",
            #[cfg(feature = "date")]
            Self::Date => "siros:date",
            #[cfg(feature = "date")]
            Self::Time => "siros:time",
            #[cfg(feature = "date")]
            Self::DateTime => "siros:datetime",
            #[cfg(feature = "conformance")]
            Self::Test => "test:function",
            #[cfg(feature = "conformance")]
            Self::TestSelect => "test:select",
            #[cfg(feature = "conformance")]
            Self::TestFormat => "test:format",
        }
    }

    /// The family whose check and resolution it shares.
    const fn family(self) -> Family {
        match self {
            Self::String => Family::String,
            #[cfg(feature = "number")]
            Self::Number | Self::Integer => Family::Numeric,
            #[cfg(feature = "offset")]
            Self::Offset => Family::Numeric,
            #[cfg(feature = "currency")]
            Self::Currency | Self::Percent => Family::Numeric,
            #[cfg(feature = "date")]
            Self::Date | Self::Time | Self::DateTime => Family::Date,
            #[cfg(feature = "conformance")]
            Self::Test | Self::TestSelect | Self::TestFormat => Family::Test,
        }
    }

    /// The section that defines its options; `None` for a function that takes none.
    pub(crate) const fn section(self) -> Option<Section> {
        match self {
            Self::String => None,
            #[cfg(feature = "number")]
            Self::Number | Self::Integer => Some(Section::Number),
            #[cfg(feature = "offset")]
            Self::Offset => Some(Section::Offset),
            #[cfg(feature = "currency")]
            Self::Currency | Self::Percent => Some(Section::Currency),
            #[cfg(feature = "date")]
            Self::Date | Self::Time | Self::DateTime => Some(Section::Date),
            #[cfg(feature = "conformance")]
            Self::Test | Self::TestSelect | Self::TestFormat => None,
        }
    }
}

/// The functions that share a check and a resolution.
enum Family {
    String,
    #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
    Numeric,
    #[cfg(feature = "date")]
    Date,
    #[cfg(feature = "conformance")]
    Test,
}

/// The numeric chain's language: the section of the function that formats its value. `:offset`
/// formats with the function of its operand's call, and with `[formats.offset]` over `:number`,
/// `:integer` or a literal.
///
/// # Errors
///
/// [`Refused::Undefined`] for a section no module defined, and [`Refusal::Operand`] for a chain
/// with a call of another family.
#[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
fn language<'f>(
    chain: &Chain<'_>,
    formats: &'f Formats,
) -> Result<crate::numeric::Language<'f>, Refused> {
    #[cfg(any(feature = "number", feature = "currency"))]
    use crate::numeric::options::Function as Numeric;
    let formatter = crate::numeric::formatter(chain).ok_or(Refusal::Operand)?;
    match (chain.outer.function, formatter) {
        #[cfg(feature = "currency")]
        (_, Numeric::Currency | Numeric::Percent) => Ok(crate::numeric::Language::Currency(
            formats.currency().ok_or(Refused::Undefined)?,
        )),
        #[cfg(feature = "offset")]
        (Function::Offset, _) => Ok(crate::numeric::Language::Plain(
            formats.offset().ok_or(Refused::Undefined)?,
        )),
        #[cfg(feature = "number")]
        (_, Numeric::Number | Numeric::Integer | Numeric::Offset) => Ok(
            crate::numeric::Language::Plain(formats.number().ok_or(Refused::Undefined)?),
        ),
        #[cfg(not(all(feature = "number", feature = "currency")))]
        _ => Err(Refusal::Operand.into()),
    }
}

/// The numeric chain's language at resolution.
///
/// # Errors
///
/// [`Failure::Operand`] for a chain no section of the context formats.
#[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
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
        not(feature = "conformance"),
        expect(
            unused_variables,
            reason = "only the test functions tell the uses apart"
        )
    )]
    at: Use,
    #[cfg_attr(
        not(any(
            feature = "number",
            feature = "currency",
            feature = "offset",
            feature = "date"
        )),
        expect(unused_variables, reason = "only the format functions read a section")
    )]
    formats: &Formats,
) -> Result<(), Refused> {
    match chain.outer.function.family() {
        Family::String => crate::string::check(chain),
        #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
        Family::Numeric => crate::numeric::check(chain, language(chain, formats)?),
        #[cfg(feature = "date")]
        Family::Date => {
            if formats.date().is_none() {
                return Err(Refused::Undefined);
            }
            Ok(crate::date::check(chain)?)
        }
        #[cfg(feature = "conformance")]
        Family::Test => crate::test_functions::check(chain, at),
    }
}

/// How a selector's function selects.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Selecting {
    /// `:string`: the key equal to the operand's text.
    Text,
    /// A numeric function: by its `select`.
    #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
    Number(crate::numeric::Selection),
    /// A test function.
    #[cfg(feature = "conformance")]
    Test,
}

impl Selecting {
    /// How the chain selects, checked for its use as a selector against the sections of the
    /// modules loaded so far, a literal it compares held by `hold`.
    ///
    /// # Errors
    ///
    /// [`Refused`] for a section no module defined, a call the function refuses, or a literal
    /// `hold` refuses: a function that does not select refuses with [`Refusal::Selector`].
    pub(crate) fn of(
        chain: &Chain<'_>,
        #[cfg_attr(
            not(any(feature = "number", feature = "currency", feature = "offset")),
            expect(unused_variables, reason = "only the numeric functions read a section")
        )]
        formats: &Formats,
        hold: Hold,
    ) -> Result<Self, Refused> {
        match chain.outer.function.family() {
            Family::String => crate::string::selecting(chain, hold).map(|()| Self::Text),
            #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
            Family::Numeric => {
                crate::numeric::selection(chain, language(chain, formats)?).map(Self::Number)
            }
            #[cfg(feature = "date")]
            Family::Date => Err(Refusal::Selector.into()),
            #[cfg(feature = "conformance")]
            Family::Test => crate::test_functions::selecting(chain).map(|()| Self::Test),
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
            not(any(feature = "number", feature = "currency", feature = "offset")),
            expect(unused_variables, reason = "only the numeric selection refuses a key")
        )]
        key: &str,
    ) -> Result<(), Refusal> {
        match self {
            #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
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
            not(any(
                feature = "number",
                feature = "currency",
                feature = "offset",
                feature = "conformance"
            )),
            expect(unused_variables, reason = "`:string` reads no option")
        )]
        texts: &Texts<'_>,
        scope: &Scope<'s>,
    ) -> Result<Selected<'s>, Failure> {
        match self {
            Self::Text => crate::string::selected(chain, scope).map(Selected::Text),
            #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
            Self::Number(selection) => {
                let language = formatting(chain, scope.formats)?;
                crate::numeric::selected(chain, texts, scope, language, selection)
                    .map(Selected::Number)
            }
            #[cfg(feature = "conformance")]
            Self::Test => crate::test_functions::selected(chain, texts, scope).map(Selected::Test),
        }
    }
}

/// What a selector's value selects with.
#[derive(Debug)]
pub(crate) enum Selected<'s> {
    /// The text a key equals.
    Text(Cow<'s, str>),
    /// A number's exact key and plural category.
    #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
    Number(crate::numeric::Selected),
    /// The keys a test function's value matches, best first.
    #[cfg(feature = "conformance")]
    Test(&'static [&'static str]),
}

impl Selected<'_> {
    /// The rank of `key` among the keys the value matches, from 0 for the best; `None` for a key
    /// it does not match.
    pub(crate) fn rank(&self, key: &str) -> Option<usize> {
        match self {
            Self::Text(text) => (text.as_ref() == key).then_some(0),
            #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
            Self::Number(number) => number.rank(key),
            #[cfg(feature = "conformance")]
            Self::Test(matched) => matched.iter().position(|text| *text == key),
        }
    }
}

/// The chain's value as an option's value: the operand's text for `:string` and the date
/// functions, the number for the numeric functions, and the test functions' input.
///
/// # Errors
///
/// [`Failure`] as [`format`].
pub(crate) fn value<'m>(chain: &Chain<'m>, scope: &Scope<'m>) -> Result<Cow<'m, str>, Failure> {
    #[cfg_attr(
        not(any(
            feature = "number",
            feature = "currency",
            feature = "offset",
            feature = "date",
            feature = "conformance"
        )),
        expect(unused_variables, reason = "`:string` reads no option")
    )]
    let texts = chain.texts(scope)?;
    match chain.outer.function.family() {
        Family::String => crate::string::value(chain, scope).map(Cow::Borrowed),
        #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
        Family::Numeric => {
            let language = formatting(chain, scope.formats)?;
            crate::numeric::value(chain, &texts, scope, language).map(Cow::Owned)
        }
        #[cfg(feature = "date")]
        Family::Date => crate::date::value(chain, &texts, scope).map(Cow::Borrowed),
        #[cfg(feature = "conformance")]
        Family::Test => crate::test_functions::value(chain, &texts, scope).map(Cow::Borrowed),
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
        not(any(
            feature = "number",
            feature = "currency",
            feature = "offset",
            feature = "date",
            feature = "conformance"
        )),
        expect(unused_variables, reason = "`:string` reads no option")
    )]
    texts: &Texts<'_>,
    scope: &Scope<'_>,
) -> Result<(String, Direction), Failure> {
    match chain.outer.function.family() {
        Family::String => {
            crate::string::value(chain, scope).map(|text| (text.to_owned(), Direction::Unknown))
        }
        #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
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
        #[cfg(feature = "conformance")]
        Family::Test => crate::test_functions::format(chain, texts, scope)
            .map(|text| (text, Direction::Unknown)),
    }
}
