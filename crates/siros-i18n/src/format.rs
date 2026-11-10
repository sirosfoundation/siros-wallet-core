//! The build's functions, one family per feature: `:string` always, `:number` and `:integer`
//! (`number`), `:offset` (`offset`), `:currency` and `:percent` (`currency`), `:siros:date`,
//! `:siros:time` and `:siros:datetime` (`date`), and MF2's test functions (`conformance`). A
//! family with options parses its `[formats.<format>]` section; the compiler hands each family the
//! call chains whose outermost call is one of its functions, and the compiled call formats and
//! selects at resolution.

use crate::error::{FormatRule, LoadError, Refusal};
use crate::normal::{Hold, Unnormalized};
#[cfg(any(
    feature = "number",
    feature = "currency",
    feature = "offset",
    feature = "date"
))]
use crate::resource::Entry;
use crate::resource::FormatSection;

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

    /// The section that defines its options; `None` for a function that takes none.
    const fn section(self) -> Option<Section> {
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

/// A `[formats.<format>]` section's format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Section {
    Number,
    Offset,
    Currency,
    Date,
}

impl Section {
    const ALL: [Self; 4] = [Self::Number, Self::Offset, Self::Currency, Self::Date];

    fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|section| section.name() == name)
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Number => "number",
            Self::Offset => "offset",
            Self::Currency => "currency",
            Self::Date => "date",
        }
    }
}

/// What an expression's chain of calls starts from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Root {
    /// No operand: `{:function}`.
    None,
    /// A literal's string value.
    Literal(String),
    /// The argument of this key.
    Argument(String),
}

/// An option's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OptionValue {
    /// A literal written as the value.
    Literal(String),
    /// A literal a `.local` declaration binds to the variable written as the value.
    Local(String),
    /// The argument of the key a variable written as the value names.
    Argument(String),
}

/// A call of a chain: its function and its options, each name once, in the order written. The
/// `u:` options are the compiler's and stay out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallSpec {
    pub(crate) function: Function,
    pub(crate) options: Vec<(String, OptionValue)>,
}

/// An expression's calls: the root, the calls applied to it from the innermost, and the
/// outermost, whose function formats or selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Chain {
    pub(crate) root: Root,
    pub(crate) inner: Vec<CallSpec>,
    pub(crate) outer: CallSpec,
}

/// One call's options, each with its text.
#[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
#[derive(Debug)]
pub(crate) struct CallTexts<'a> {
    pub(crate) function: Function,
    pub(crate) options: Vec<(&'a str, &'a str)>,
}

impl Chain {
    /// The calls, innermost first.
    pub(crate) fn calls(&self) -> impl DoubleEndedIterator<Item = &CallSpec> {
        self.inner.iter().chain(std::iter::once(&self.outer))
    }

    /// The calls with each option's text, innermost first: a literal as written, an argument's
    /// text by `argument`.
    ///
    /// # Errors
    ///
    /// The key of an option's argument `argument` does not give.
    #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
    pub(crate) fn texts<'a>(
        &'a self,
        argument: &dyn Fn(&str) -> Option<&'a str>,
    ) -> Result<Vec<CallTexts<'a>>, String> {
        self.calls()
            .map(|call| {
                let options = call
                    .options
                    .iter()
                    .map(|(name, value)| match value {
                        OptionValue::Literal(text) | OptionValue::Local(text) => {
                            Ok((name.as_str(), text.as_str()))
                        }
                        OptionValue::Argument(key) => argument(key)
                            .map(|text| (name.as_str(), text))
                            .ok_or_else(|| key.clone()),
                    })
                    .collect::<Result<_, _>>()?;
                Ok(CallTexts {
                    function: call.function,
                    options,
                })
            })
            .collect()
    }

    /// The keys of the arguments the chain reads: its operand's and its options'.
    #[cfg(feature = "check")]
    pub(crate) fn reads(&self) -> Vec<String> {
        let root = match &self.root {
            Root::Argument(key) => Some(key.clone()),
            Root::None | Root::Literal(_) => None,
        };
        let options = self.calls().flat_map(|call| {
            call.options.iter().filter_map(|(_, value)| match value {
                OptionValue::Argument(key) => Some(key.clone()),
                OptionValue::Literal(_) | OptionValue::Local(_) => None,
            })
        });
        root.into_iter().chain(options).collect()
    }

    /// The calls with each option's literal text; `None` when an argument gives one.
    #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
    pub(crate) fn literal_texts(&self) -> Option<Vec<CallTexts<'_>>> {
        self.texts(&|_| None).ok()
    }
}

/// Why a compiled call does not format or select a value at resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The function refuses the operand's text.
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "date",
        feature = "conformance"
    ))]
    Operand,
    /// The function refuses an option's text, which an argument gives.

    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "date"
    ))]
    Option(String),
    /// The argument of this key, which the message does not give: the operand's or an
    /// option's.
    Unresolved(String),
}

/// Why the compiler refuses a call chain.
#[derive(Debug)]
pub(crate) enum Refused {
    /// The outermost function's options are defined by no module loaded so far.
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "date"
    ))]
    Undefined,
    /// The function refuses the call.
    Call(Refusal),
    /// A selector's literal the load's [`Hold`] refuses.
    Unnormalized(Unnormalized),
}

impl From<Refusal> for Refused {
    fn from(refusal: Refusal) -> Self {
        Self::Call(refusal)
    }
}

/// The arguments' texts, by key.
pub(crate) type Argument<'a> = dyn Fn(&str) -> Option<&'a str> + 'a;

/// A compiled call a placeholder formats with: its outermost function's family's compiled form.
#[derive(Debug, Clone)]
pub(crate) enum Formatter {
    String(crate::string::Compiled),
    #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
    Numeric(Box<crate::numeric::Compiled>),
    #[cfg(feature = "date")]
    Date(Box<crate::date::Compiled>),
    #[cfg(feature = "conformance")]
    Test(crate::test_functions::Compiled),
}

/// A compiled call a selector selects with: its outermost function's family's compiled form.
#[derive(Debug, Clone)]
pub(crate) enum Selector {
    String(crate::string::Compiled),
    #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
    Numeric(Box<crate::numeric::Selecting>),
    #[cfg(feature = "conformance")]
    Test(crate::test_functions::Compiled),
}

/// The numeric chain's language: the options of its section, the one of the function that formats
/// its value. `:offset` formats with the function of its operand's call, and with
/// `[formats.offset]` over `:number`, `:integer` or a literal.
#[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
fn language(chain: &Chain, formats: &Formats) -> Result<crate::numeric::Language, Refused> {
    #[cfg(any(feature = "number", feature = "currency"))]
    use crate::numeric::options::Function as Numeric;
    match (chain.outer.function, crate::numeric::formatter(chain)) {
        #[cfg(feature = "currency")]
        (_, Numeric::Currency | Numeric::Percent) => Ok(formats
            .currency
            .as_ref()
            .ok_or(Refused::Undefined)?
            .language(chain)?),
        #[cfg(feature = "offset")]
        (Function::Offset, _) => Ok(crate::numeric::Language::plain(
            formats.offset.as_ref().ok_or(Refused::Undefined)?,
        )),
        #[cfg(feature = "number")]
        (_, Numeric::Number | Numeric::Integer | Numeric::Offset) => Ok(
            crate::numeric::Language::plain(formats.number.as_ref().ok_or(Refused::Undefined)?),
        ),
        #[cfg(not(all(feature = "number", feature = "currency")))]
        _ => Err(Refused::Call(Refusal::Operand)),
    }
}

/// The numeric chain compiled for a placeholder.
#[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
fn numeric(chain: &Chain, formats: &Formats) -> Result<Formatter, Refused> {
    let compiled = crate::numeric::compile(chain, language(chain, formats)?)?;
    Ok(Formatter::Numeric(Box::new(compiled)))
}

/// The numeric chain compiled for a selector over `keys`.
#[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
fn numeric_selector(
    chain: &Chain,
    keys: &[String],
    formats: &Formats,
) -> Result<Selector, Refused> {
    let selecting = crate::numeric::selecting(chain, language(chain, formats)?)?;
    crate::numeric::keys(keys)?;
    Ok(Selector::Numeric(Box::new(selecting)))
}

impl Formatter {
    /// The chain compiled by its outermost function for a placeholder.
    ///
    /// # Errors
    ///
    /// [`Refused`] for a section no module defined, or a call the function refuses.
    pub(crate) fn compile(
        chain: &Chain,
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
    ) -> Result<Self, Refused> {
        match chain.outer.function {
            Function::String => Ok(Self::String(crate::string::compile(chain)?)),
            #[cfg(feature = "number")]
            Function::Number | Function::Integer => numeric(chain, formats),
            #[cfg(feature = "offset")]
            Function::Offset => numeric(chain, formats),
            #[cfg(feature = "currency")]
            Function::Currency | Function::Percent => numeric(chain, formats),
            #[cfg(feature = "date")]
            Function::Date | Function::Time | Function::DateTime => {
                let section = formats.date.as_ref().ok_or(Refused::Undefined)?;
                Ok(Self::Date(Box::new(crate::date::compile(chain, section)?)))
            }
            #[cfg(feature = "conformance")]
            Function::Test | Function::TestSelect | Function::TestFormat => Ok(Self::Test(
                crate::test_functions::compile(chain, crate::test_functions::Use::Format)?,
            )),
        }
    }

    /// The direction of the value's formatted text.
    pub(crate) fn direction(&self) -> Direction {
        match self {
            Self::String(_) => Direction::Unknown,
            #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
            Self::Numeric(compiled) => compiled.direction(),
            #[cfg(feature = "date")]
            Self::Date(compiled) => compiled.direction(),
            #[cfg(feature = "conformance")]
            Self::Test(_) => Direction::Unknown,
        }
    }

    /// The value formatted, its operand and its options' arguments read from `argument`.
    ///
    /// # Errors
    ///
    /// [`Failure`] for an operand or an option text the function refuses, or an argument the
    /// message does not give.
    pub(crate) fn format<'a>(&'a self, argument: &Argument<'a>) -> Result<String, Failure> {
        match self {
            Self::String(compiled) => compiled.format(argument).map(str::to_owned),
            #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
            Self::Numeric(compiled) => compiled.format(argument),
            #[cfg(feature = "date")]
            Self::Date(compiled) => compiled.format(argument),
            #[cfg(feature = "conformance")]
            Self::Test(compiled) => compiled.format(argument),
        }
    }
}

impl Selector {
    /// The chain compiled by its outermost function for a selector, with the variant keys of
    /// its column, a literal `:string` compares held by `hold`.
    ///
    /// # Errors
    ///
    /// [`Refused`] for a section no module defined, a call the function refuses, or a literal
    /// `hold` refuses: a function that does not select refuses with [`Refusal::Selector`], a key
    /// its selection does not read with [`Refusal::Key`].
    pub(crate) fn compile(
        chain: &Chain,
        #[cfg_attr(
            not(any(feature = "number", feature = "currency", feature = "offset")),
            expect(unused_variables, reason = "only the numeric selection refuses a key")
        )]
        keys: &[String],
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
        hold: Hold,
    ) -> Result<Self, Refused> {
        match chain.outer.function {
            Function::String => Ok(Self::String(crate::string::selector(chain, hold)?)),
            #[cfg(feature = "number")]
            Function::Number | Function::Integer => numeric_selector(chain, keys, formats),
            #[cfg(feature = "offset")]
            Function::Offset => numeric_selector(chain, keys, formats),
            #[cfg(feature = "currency")]
            Function::Currency | Function::Percent => numeric_selector(chain, keys, formats),
            #[cfg(feature = "date")]
            Function::Date | Function::Time | Function::DateTime => {
                if formats.date.is_none() {
                    return Err(Refused::Undefined);
                }
                Err(Refused::Call(Refusal::Selector))
            }
            #[cfg(feature = "conformance")]
            Function::Test | Function::TestSelect | Function::TestFormat => Ok(Self::Test(
                crate::test_functions::compile(chain, crate::test_functions::Use::Select)?,
            )),
        }
    }

    /// The keys among `keys` the value matches, best first, its operand and its options'
    /// arguments read from `argument`.
    ///
    /// # Errors
    ///
    /// [`Failure`] as [`Formatter::format`].
    pub(crate) fn select<'a, 'k>(
        &'a self,
        argument: &Argument<'a>,
        keys: &'k [String],
    ) -> Result<Vec<&'k str>, Failure> {
        match self {
            Self::String(compiled) => compiled.select(argument, keys),
            #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
            Self::Numeric(compiled) => compiled.select(argument, keys),
            #[cfg(feature = "conformance")]
            Self::Test(compiled) => compiled.select(argument, keys),
        }
    }
}

/// A format section's options, each name once, each one its format takes; and the direction of
/// the module that defines it.
#[cfg(any(
    feature = "number",
    feature = "currency",
    feature = "offset",
    feature = "date"
))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Options<'s> {
    entries: &'s [Entry],
    pub(crate) direction: Direction,
}

#[cfg(any(
    feature = "number",
    feature = "currency",
    feature = "offset",
    feature = "date"
))]
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
            .map(|entry| entry.value.as_str())
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
    #[cfg(feature = "offset")]
    offset: Option<crate::numeric::Plain>,
    #[cfg(feature = "currency")]
    currency: Option<crate::numeric::currency::Parsed>,
    #[cfg(feature = "date")]
    date: Option<crate::date::Parsed>,
}

impl Formats {
    /// Defines a section of a module whose direction is `direction`.
    ///
    /// # Errors
    ///
    /// [`LoadError::Repeated`] for a section the context holds or an option given twice,
    /// [`LoadError::Format`] for a section its format refuses.
    pub(crate) fn define(
        &mut self,
        section: &FormatSection,
        #[cfg_attr(
            not(any(
                feature = "number",
                feature = "currency",
                feature = "offset",
                feature = "date"
            )),
            expect(unused_variables, reason = "a build without formats parses no section")
        )]
        direction: Direction,
    ) -> Result<(), LoadError> {
        let refuse = |rule| LoadError::Format {
            format: section.format.clone(),
            rule,
        };
        let Some(named) = Section::named(&section.format) else {
            return Err(refuse(FormatRule::Unknown));
        };
        if self.defined.contains(&named) {
            return Err(LoadError::Repeated {
                id: format!("formats.{}", section.format),
            });
        }
        for (index, entry) in section.options.iter().enumerate() {
            if section
                .options
                .iter()
                .take(index)
                .any(|earlier| earlier.key == entry.key)
            {
                return Err(LoadError::Repeated {
                    id: format!("formats.{}.{}", section.format, entry.key),
                });
            }
        }
        #[cfg(any(
            feature = "number",
            feature = "currency",
            feature = "offset",
            feature = "date"
        ))]
        self.parse(
            named,
            Options {
                entries: &section.options,
                direction,
            },
        )
        .map_err(refuse)?;
        self.defined.push(named);
        Ok(())
    }

    /// Parses a section of a format the build compiles in; a section of another format stays
    /// unparsed.
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "date"
    ))]
    fn parse(&mut self, section: Section, options: Options<'_>) -> Result<(), FormatRule> {
        match section {
            #[cfg(feature = "number")]
            Section::Number => {
                takes(options, &crate::numeric::PLAIN)?;
                self.number = Some(crate::numeric::Plain::parse(options)?);
            }
            #[cfg(feature = "offset")]
            Section::Offset => {
                takes(options, &crate::numeric::PLAIN)?;
                self.offset = Some(crate::numeric::Plain::parse(options)?);
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
            #[cfg(not(all(
                feature = "number",
                feature = "offset",
                feature = "currency",
                feature = "date"
            )))]
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
#[cfg(any(
    feature = "number",
    feature = "currency",
    feature = "offset",
    feature = "date"
))]
fn takes(options: Options<'_>, names: &[&str]) -> Result<(), FormatRule> {
    match options
        .entries
        .iter()
        .find(|entry| !names.contains(&entry.key.as_str()))
    {
        Some(entry) => Err(FormatRule::Undefined {
            option: entry.key.clone(),
        }),
        None => Ok(()),
    }
}
