//! The date module: `:siros:date`, `:siros:time` and `:siros:datetime`, which format a date, a
//! time or both in the Gregorian calendar with the language's CLDR patterns at a `length`
//! (`short`, `medium`, `long`, `full`; Unicode TR35 Part 4, "Date Format Patterns"). A time
//! without an offset shows at `long` and `full` as at `medium`: those patterns name its zone. A
//! year outside 1950 to 2049 shows in full, and one before 1000 with its era, as ICU4X's
//! `YearStyle::Auto` shows them.

use siros_explain::{Date, Offset, Value, checked};

use crate::bytes::Reader;
use crate::error::{FormatFailure, RenderError};
use crate::format::{Direction, FormatId, FormatRenderer, Input, VariantKey, VariantKeys};
use crate::sink::Sink;

#[cfg(feature = "load")]
mod load;

/// The date module, both halves.
#[derive(Debug)]
pub struct DateFormat;

/// The date module a build registers.
pub static DATE: DateFormat = DateFormat;

const ID: FormatId = checked!(FormatId, "date");

/// What a placeholder formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Date,
    Time,
    DateTime,
}

/// A pattern's item.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item<'a> {
    Text(&'a str),
    Field(u8, u8),
}

/// A value's calendar fields.
struct Moment {
    date: Option<Date>,
    hour: u8,
    minute: u8,
    second: u8,
    /// The fraction's nanoseconds.
    nanos: u32,
    offset: Option<Offset>,
}

impl Moment {
    fn of(kind: Kind, input: &Input<'_>) -> Result<Self, RenderError> {
        let bad = RenderError::Message(FormatFailure::BadOperand);
        let time = |at: siros_explain::Time, date, offset| Self {
            date,
            hour: at.hour(),
            minute: at.minute(),
            second: at.second().map_or(0, |s| s.whole()),
            nanos: at.second().map_or(0, |s| s.fraction().nanos()),
            offset,
        };
        let midnight = |date| Self {
            date: Some(date),
            hour: 0,
            minute: 0,
            second: 0,
            nanos: 0,
            offset: None,
        };
        match (kind, input) {
            (Kind::Date, Input::Value(Value::Date(date))) => Ok(midnight(*date)),
            (Kind::Time, Input::Value(Value::Time { at, offset })) => Ok(time(*at, None, *offset)),
            (_, Input::Value(Value::DateTime(value))) => Ok(Self {
                date: Some(value.date()),
                hour: value.hour(),
                minute: value.minute(),
                second: value.second().unwrap_or(0),
                nanos: value.fraction().nanos(),
                offset: value.offset(),
            }),
            _ => Err(bad),
        }
    }

    /// The day of the week, 0 for Sunday.
    fn weekday(date: Date) -> usize {
        const SHIFT: [u32; 12] = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
        let month = date.month();
        let year = u32::from(date.year()) - u32::from(month < 3);
        let shift = SHIFT
            .get(usize::from(month).saturating_sub(1))
            .copied()
            .unwrap_or(0);
        ((year + year / 4 - year / 100 + year / 400 + shift + u32::from(date.day())) % 7) as usize
    }
}

/// A compiled placeholder, read.
struct Form<'a> {
    kind: Kind,
    zero: char,
    direction: Direction,
    date: Vec<Item<'a>>,
    time: Vec<Item<'a>>,
    /// The time pattern for a value without an offset.
    unzoned: Vec<Item<'a>>,
    glue: Vec<Item<'a>>,
    months: Vec<&'a str>,
    days: Vec<&'a str>,
    periods: Vec<&'a str>,
    gmt: &'a str,
    hours: [Vec<Item<'a>>; 2],
    /// A year with its era, CLDR's `Gy` pattern; empty without a date.
    year_era: Vec<Item<'a>>,
    /// The eras' abbreviated names: before year 1, then from it.
    eras: Vec<&'a str>,
}

/// What a Gregorian year needs beside its last two digits to be read unambiguously, as ICU4X
/// 2.4 decides it (icu_calendar `cal/gregorian.rs`, `YearAmbiguity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ambiguity {
    /// 1950 to 2049: none.
    Unambiguous,
    /// 1000 to 1949, and from 2050: its century.
    Century,
    /// Before 1000: its era and its century.
    EraAndCentury,
}

impl Ambiguity {
    const fn of(year: u16) -> Self {
        match year {
            ..=999 => Self::EraAndCentury,
            1950..=2049 => Self::Unambiguous,
            _ => Self::Century,
        }
    }
}

/// A year in its era: year 0 is 1 before year 1 (era 0), every later year its own (era 1).
fn in_era(year: u16) -> (usize, u32) {
    match year {
        0 => (0, 1),
        year => (1, u32::from(year)),
    }
}

fn items<'a>(reader: &mut Reader<'a>) -> Result<Vec<Item<'a>>, RenderError> {
    (0..reader.count()?)
        .map(|_| match reader.byte()? {
            0 => Ok(Item::Text(reader.text()?)),
            1 => Ok(Item::Field(reader.byte()?, reader.byte()?)),
            _ => Err(reader.malformed()),
        })
        .collect()
}

fn texts<'a>(reader: &mut Reader<'a>) -> Result<Vec<&'a str>, RenderError> {
    (0..reader.count()?).map(|_| reader.text()).collect()
}

impl<'a> Form<'a> {
    fn read(bytes: &'a [u8]) -> Result<Self, RenderError> {
        let mut reader = Reader::new(bytes, ID);
        let kind = match reader.byte()? {
            0 => Kind::Date,
            1 => Kind::Time,
            2 => Kind::DateTime,
            _ => return Err(reader.malformed()),
        };
        let zero = {
            let mut chars = reader.text()?.chars();
            match (chars.next(), chars.next()) {
                (Some(zero), None) => zero,
                _ => return Err(reader.malformed()),
            }
        };
        let direction = match reader.byte()? {
            0 => Direction::Ltr,
            1 => Direction::Rtl,
            2 => Direction::Unknown,
            _ => return Err(reader.malformed()),
        };
        Ok(Self {
            kind,
            zero,
            direction,
            date: items(&mut reader)?,
            time: items(&mut reader)?,
            unzoned: items(&mut reader)?,
            glue: items(&mut reader)?,
            months: texts(&mut reader)?,
            days: texts(&mut reader)?,
            periods: texts(&mut reader)?,
            gmt: reader.text()?,
            hours: [items(&mut reader)?, items(&mut reader)?],
            year_era: items(&mut reader)?,
            eras: texts(&mut reader)?,
        })
    }

    fn digits(&self, value: u32, width: u8, out: &mut String) {
        let text = format!("{value:0>width$}", width = usize::from(width));
        let zero = u32::from(self.zero);
        out.extend(
            text.bytes()
                .map(|b| char::from_u32(zero + u32::from(b - b'0')).unwrap_or(self.zero)),
        );
    }

    fn name(names: &[&str], index: usize, out: &mut String) -> Result<(), RenderError> {
        out.push_str(names.get(index).ok_or(RenderError::Compiled(ID))?);
        Ok(())
    }

    /// The localized GMT format of an offset: `long` pads its hours and writes its minutes.
    fn zone(&self, offset: Offset, long: bool, out: &mut String) -> Result<(), RenderError> {
        let minutes = offset.minutes();
        let pattern = self
            .hours
            .get(usize::from(minutes < 0))
            .ok_or(RenderError::Compiled(ID))?;
        let (hours, rest) = (
            u32::from(minutes.unsigned_abs() / 60),
            u32::from(minutes.unsigned_abs() % 60),
        );
        let mut text = String::new();
        let mut pending = String::new();
        for item in pattern {
            match *item {
                Item::Text(literal) => pending.push_str(literal),
                Item::Field(b'H', _) => {
                    text.push_str(&std::mem::take(&mut pending));
                    self.digits(hours, if long { 2 } else { 1 }, &mut text);
                }
                Item::Field(b'm', _) => {
                    let literal = std::mem::take(&mut pending);
                    if long || rest != 0 {
                        text.push_str(&literal);
                        self.digits(rest, 2, &mut text);
                    }
                }
                Item::Field(..) => return Err(RenderError::Compiled(ID)),
            }
        }
        text.push_str(&pending);
        out.push_str(&self.gmt.replace("{0}", &text));
        Ok(())
    }

    fn pattern(
        &self,
        pattern: &[Item<'_>],
        moment: &Moment,
        out: &mut String,
    ) -> Result<(), RenderError> {
        let shows_era = pattern
            .iter()
            .any(|item| matches!(item, Item::Field(b'G', _)));
        for item in pattern {
            let (letter, width) = match *item {
                Item::Text(text) => {
                    out.push_str(text);
                    continue;
                }
                Item::Field(letter, width) => (letter, width),
            };
            if letter == b'y' {
                let date = moment.date.ok_or(RenderError::Compiled(ID))?;
                self.year(date.year(), width, shows_era, out)?;
            } else {
                self.field(letter, width, moment, out)?;
            }
        }
        Ok(())
    }

    /// A year field: its last two digits for `yy`, unless ICU4X's `YearStyle::Auto` needs
    /// more; then the full year, and before year 1000 the year in its era with the era, by the
    /// `Gy` pattern, when the pattern shows no era of its own.
    fn year(
        &self,
        year: u16,
        width: u8,
        shows_era: bool,
        out: &mut String,
    ) -> Result<(), RenderError> {
        match (Ambiguity::of(year), shows_era) {
            (Ambiguity::EraAndCentury, false) => {
                for item in &self.year_era {
                    match *item {
                        Item::Text(text) => out.push_str(text),
                        Item::Field(b'y', width) => self.digits(in_era(year).1, width, out),
                        Item::Field(b'G', _) => Self::name(&self.eras, in_era(year).0, out)?,
                        Item::Field(..) => return Err(RenderError::Compiled(ID)),
                    }
                }
            }
            (Ambiguity::EraAndCentury, true) => {
                self.digits(in_era(year).1, if width == 2 { 1 } else { width }, out);
            }
            (Ambiguity::Unambiguous, _) if width == 2 => {
                self.digits(u32::from(year) % 100, 2, out);
            }
            (Ambiguity::Century, _) if width == 2 => self.digits(u32::from(year), 1, out),
            (Ambiguity::Unambiguous | Ambiguity::Century, _) => {
                self.digits(u32::from(year), width, out);
            }
        }
        Ok(())
    }

    fn field(
        &self,
        letter: u8,
        width: u8,
        moment: &Moment,
        out: &mut String,
    ) -> Result<(), RenderError> {
        let malformed = RenderError::Compiled(ID);
        let date = || moment.date.ok_or(RenderError::Compiled(ID));
        match letter {
            b'G' => Self::name(&self.eras, in_era(date()?.year()).0, out)?,
            b'M' if width >= 3 => {
                let index = usize::from(date()?.month() - 1) + if width == 3 { 12 } else { 0 };
                Self::name(&self.months, index, out)?;
            }
            b'M' => self.digits(u32::from(date()?.month()), width, out),
            b'd' => self.digits(u32::from(date()?.day()), width, out),
            b'E' => {
                let index = Moment::weekday(date()?) + if width == 4 { 0 } else { 7 };
                Self::name(&self.days, index, out)?;
            }
            b'h' => self.digits(u32::from((moment.hour + 11) % 12 + 1), width, out),
            b'H' => self.digits(u32::from(moment.hour), width, out),
            b'K' => self.digits(u32::from(moment.hour % 12), width, out),
            b'k' => self.digits(u32::from((moment.hour + 23) % 24 + 1), width, out),
            b'm' => self.digits(u32::from(moment.minute), width, out),
            b's' => self.digits(u32::from(moment.second), width, out),
            b'S' => {
                let nanos = format!("{:09}", moment.nanos);
                let shown = nanos.get(..usize::from(width).min(9)).unwrap_or_default();
                let value: u32 = shown.parse().map_err(|_| RenderError::Compiled(ID))?;
                self.digits(value, width, out);
            }
            b'a' => Self::name(&self.periods, usize::from(moment.hour >= 12), out)?,
            b'z' | b'O' => {
                let offset = moment.offset.ok_or(malformed)?;
                self.zone(offset, width == 4, out)?;
            }
            _ => return Err(malformed),
        }
        Ok(())
    }

    fn time(&self, moment: &Moment, out: &mut String) -> Result<(), RenderError> {
        let pattern = if moment.offset.is_some() {
            &self.time
        } else {
            &self.unzoned
        };
        self.pattern(pattern, moment, out)
    }

    fn render(&self, moment: &Moment) -> Result<String, RenderError> {
        let mut out = String::new();
        match self.kind {
            Kind::Date => self.pattern(&self.date, moment, &mut out)?,
            Kind::Time => self.time(moment, &mut out)?,
            Kind::DateTime => {
                for item in &self.glue {
                    match *item {
                        Item::Text(text) => out.push_str(text),
                        Item::Field(0, _) => self.time(moment, &mut out)?,
                        Item::Field(1, _) => self.pattern(&self.date, moment, &mut out)?,
                        Item::Field(..) => return Err(RenderError::Compiled(ID)),
                    }
                }
            }
        }
        Ok(out)
    }
}

impl FormatRenderer for DateFormat {
    fn id(&self) -> FormatId {
        ID
    }

    fn direction(&self, compiled: &[u8], _input: &Input<'_>) -> Result<Direction, RenderError> {
        Form::read(compiled).map(|form| form.direction)
    }

    fn render(
        &self,
        compiled: &[u8],
        input: &Input<'_>,
        sink: &mut dyn Sink,
    ) -> Result<(), RenderError> {
        let form = Form::read(compiled)?;
        let moment = Moment::of(form.kind, input)?;
        sink.text(&form.render(&moment)?);
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
