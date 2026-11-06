//! The list module: `:siros:list`, which joins its argument's items as the language's and-list or
//! or-list, the list's kind (Unicode TR35 Part 2, "List Patterns"). A kind's special case
//! replaces its end and pair patterns before an item its condition matches.

mod condition;

use siros_explain::{ListKind, checked};

use crate::bytes::Reader;
use crate::error::{FormatFailure, RenderError};
use crate::format::{Direction, FormatId, FormatRenderer, Input, VariantKey, VariantKeys};
use crate::sink::Sink;
use condition::Condition;

/// The list module, both halves.
#[derive(Debug)]
pub struct ListFormat;

/// The list module a build registers.
pub static LIST: ListFormat = ListFormat;

const ID: FormatId = checked!(FormatId, "list");

/// A list pattern `<before>{0}<between>{1}<after>`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Joiner {
    before: String,
    between: String,
    after: String,
}

impl Joiner {
    fn join(&self, first: &str, second: &str) -> String {
        [
            self.before.as_str(),
            first,
            &self.between,
            second,
            &self.after,
        ]
        .concat()
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self, RenderError> {
        Ok(Self {
            before: reader.text()?.to_owned(),
            between: reader.text()?.to_owned(),
            after: reader.text()?.to_owned(),
        })
    }
}

/// One kind's patterns, and its special case.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Patterns {
    start: Joiner,
    middle: Joiner,
    end: Joiner,
    pair: Joiner,
    special: Option<(Condition, Joiner)>,
}

impl Patterns {
    fn read(reader: &mut Reader<'_>) -> Result<Self, RenderError> {
        Ok(Self {
            start: Joiner::read(reader)?,
            middle: Joiner::read(reader)?,
            end: Joiner::read(reader)?,
            pair: Joiner::read(reader)?,
            special: if reader.flag()? {
                Some((Condition::read(reader)?, Joiner::read(reader)?))
            } else {
                None
            },
        })
    }

    /// `joiner`, or the special case's when its condition matches `following`.
    fn before<'p>(&'p self, joiner: &'p Joiner, following: &str) -> &'p Joiner {
        match &self.special {
            Some((condition, special)) if condition.matches(following) => special,
            _ => joiner,
        }
    }

    fn join(&self, items: &[String]) -> String {
        match items {
            [] => String::new(),
            [only] => only.clone(),
            [first, second] => self.before(&self.pair, second).join(first, second),
            [first, middle @ .., penultimate, last] => {
                let end = self.before(&self.end, last).join(penultimate, last);
                let joined = middle
                    .iter()
                    .rev()
                    .fold(end, |rest, item| self.middle.join(item, &rest));
                self.start.join(first, &joined)
            }
        }
    }
}

impl FormatRenderer for ListFormat {
    fn id(&self) -> FormatId {
        ID
    }

    fn direction(&self, _compiled: &[u8], _input: &Input<'_>) -> Result<Direction, RenderError> {
        Ok(Direction::Unknown)
    }

    fn render(
        &self,
        compiled: &[u8],
        input: &Input<'_>,
        sink: &mut dyn Sink,
    ) -> Result<(), RenderError> {
        let Input::List { kind, items } = input else {
            return Err(RenderError::Message(FormatFailure::BadOperand));
        };
        let mut reader = Reader::new(compiled, ID);
        let and = Patterns::read(&mut reader)?;
        let or = Patterns::read(&mut reader)?;
        let patterns = match kind {
            ListKind::And => and,
            ListKind::Or => or,
        };
        sink.text(&patterns.join(items.items()));
        Ok(())
    }

    fn select<'k>(
        &self,
        _compiled: &[u8],
        _input: &Input<'_>,
        _keys: VariantKeys<'k>,
    ) -> Result<Vec<VariantKey<'k>>, RenderError> {
        Err(RenderError::Message(FormatFailure::BadSelector))
    }
}

#[cfg(feature = "load")]
mod load {
    use siros_explain::ArgKind;

    use super::condition::Condition;
    use super::{ID, Joiner, ListFormat, Patterns};
    use crate::bytes::Writer;
    use crate::error::{Refusal, RefusedOption};
    use crate::format::{Call, FormatCompiler, FormatId, LanguageFormats, Operand, ParsedFormats};

    /// The options the list module reads.
    const OPTIONS: [&str; 10] = [
        "and-start",
        "and-middle",
        "and-end",
        "and-pair",
        "and-special",
        "or-start",
        "or-middle",
        "or-end",
        "or-pair",
        "or-special",
    ];

    /// `<before>{0}<between>{1}<after>`.
    fn joiner(text: &str) -> Option<Joiner> {
        let (before, rest) = text.split_once("{0}")?;
        let (between, after) = rest.split_once("{1}")?;
        let clean = |s: &str| !s.contains("{0}") && !s.contains("{1}");
        (clean(before) && clean(between) && clean(after)).then(|| Joiner {
            before: before.to_owned(),
            between: between.to_owned(),
            after: after.to_owned(),
        })
    }

    /// Empty, or a condition's line and a pattern's line.
    fn special(text: &str) -> Option<Option<(Condition, Joiner)>> {
        if text.is_empty() {
            return Some(None);
        }
        let (condition, pattern) = text.split_once('\n')?;
        Some(Some((Condition::parse(condition)?, joiner(pattern)?)))
    }

    fn patterns(
        language: &LanguageFormats<'_>,
        names: [&'static str; 5],
    ) -> Result<Patterns, RefusedOption> {
        let option = |name: &'static str| -> Result<Joiner, RefusedOption> {
            let option = language.require(name)?;
            joiner(option.text()).ok_or_else(|| option.refuse())
        };
        let [start, middle, end, pair, case] = names;
        let case = language.require(case)?;
        Ok(Patterns {
            start: option(start)?,
            middle: option(middle)?,
            end: option(end)?,
            pair: option(pair)?,
            special: special(case.text()).ok_or_else(|| case.refuse())?,
        })
    }

    /// One language's lists.
    struct Parsed {
        and: Patterns,
        or: Patterns,
    }

    fn write_joiner(joiner: &Joiner, writer: &mut Writer) {
        writer.text(&joiner.before);
        writer.text(&joiner.between);
        writer.text(&joiner.after);
    }

    fn write_patterns(patterns: &Patterns, writer: &mut Writer) {
        for joiner in [
            &patterns.start,
            &patterns.middle,
            &patterns.end,
            &patterns.pair,
        ] {
            write_joiner(joiner, writer);
        }
        writer.flag(patterns.special.is_some());
        if let Some((condition, joiner)) = &patterns.special {
            condition.write(writer);
            write_joiner(joiner, writer);
        }
    }

    impl FormatCompiler for ListFormat {
        fn id(&self) -> FormatId {
            ID
        }

        fn functions(&self) -> &'static [&'static str] {
            &["siros:list"]
        }

        fn options(&self) -> &'static [&'static str] {
            &OPTIONS
        }

        fn parse(
            &self,
            language: &LanguageFormats<'_>,
        ) -> Result<Box<dyn ParsedFormats>, RefusedOption> {
            Ok(Box::new(Parsed {
                and: patterns(
                    language,
                    [
                        "and-start",
                        "and-middle",
                        "and-end",
                        "and-pair",
                        "and-special",
                    ],
                )?,
                or: patterns(
                    language,
                    ["or-start", "or-middle", "or-end", "or-pair", "or-special"],
                )?,
            }))
        }
    }

    /// Whether an operand is a list: a list argument, or an earlier `:siros:list` call's.
    fn list(operand: Operand<'_>) -> bool {
        match operand {
            Operand::Argument(kind) => kind == ArgKind::List,
            Operand::Call(inner) => inner.function() == "siros:list" && list(inner.operand()),
            Operand::None | Operand::Literal(_) => false,
        }
    }

    impl ParsedFormats for Parsed {
        fn compile(&self, call: &Call<'_>) -> Result<Vec<u8>, Refusal> {
            if !list(call.operand()) {
                return Err(Refusal::Operand);
            }
            if call.uses().selects() {
                return Err(Refusal::Selector);
            }
            let mut writer = Writer::default();
            write_patterns(&self.and, &mut writer);
            write_patterns(&self.or, &mut writer);
            Ok(writer.finish())
        }
    }
}
