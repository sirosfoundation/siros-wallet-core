//! `age_check`'s `range` and its bounds E and C (nym_auth catalogue, `age_check`).

use std::cmp::Ordering;

use siros_codec::date::{is_leap, Date};

/// An age in whole years: `1*DIGIT`, any base-10 integer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Age {
    /// The digits without leading zeros; `"0"` for zero.
    digits: String,
}

impl Age {
    fn parse(text: &str) -> Option<Self> {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let trimmed = text.trim_start_matches('0');
        let digits = if trimmed.is_empty() { "0" } else { trimmed };
        Some(Self {
            digits: digits.to_owned(),
        })
    }

    /// The age, when it fits `u64`.
    fn years(&self) -> Option<u64> {
        self.digits.parse().ok()
    }
}

impl Ord for Age {
    fn cmp(&self, other: &Self) -> Ordering {
        self.digits
            .len()
            .cmp(&other.digits.len())
            .then_with(|| self.digits.cmp(&other.digits))
    }
}

impl PartialOrd for Age {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A parsed `range`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AgeRange {
    /// `A-B`: age A to B, A at most B.
    Between(Age, Age),
    /// `A+`: age A or more.
    AtLeast(Age),
    /// `B-`: age B or less.
    AtMost(Age),
}

/// Why a `range` is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RangeError {
    /// The text breaks the syntax `age "-" age / age "+" / age "-"`.
    #[error("the text breaks the syntax `age \"-\" age / age \"+\" / age \"-\"`")]
    Syntax,
    /// `A-B` with A greater than B.
    #[error("`A-B` with A greater than B")]
    Inverted,
}

impl AgeRange {
    /// Parses `range` (RFC 5234 syntax of the catalogue).
    ///
    /// # Errors
    ///
    /// [`RangeError`]: the syntax, or A greater than B.
    pub fn parse(text: &str) -> Result<Self, RangeError> {
        if let Some(a) = text.strip_suffix('+') {
            return Age::parse(a).map(Self::AtLeast).ok_or(RangeError::Syntax);
        }
        if let Some(b) = text.strip_suffix('-') {
            if let Some(age) = Age::parse(b) {
                return Ok(Self::AtMost(age));
            }
        }
        let (a, b) = text.split_once('-').ok_or(RangeError::Syntax)?;
        let (a, b) = (
            Age::parse(a).ok_or(RangeError::Syntax)?,
            Age::parse(b).ok_or(RangeError::Syntax)?,
        );
        if a > b {
            return Err(RangeError::Inverted);
        }
        Ok(Self::Between(a, b))
    }

    /// E and C at the date `d`, the UTC date of the proof time.
    pub fn bounds(&self, d: Date) -> Bounds {
        match self {
            Self::Between(a, b) => Bounds {
                earliest: Some(earliest(d, b)),
                cutoff: Some(cutoff(d, a)),
            },
            Self::AtLeast(a) => Bounds {
                earliest: None,
                cutoff: Some(cutoff(d, a)),
            },
            Self::AtMost(b) => Bounds {
                earliest: Some(earliest(d, b)),
                cutoff: None,
            },
        }
    }
}

/// A bound of the birth date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// A calendar date, whose year may lie outside `0000..=9999`.
    Date(Date),
    /// A date more than `u64::MAX` years before the proof date: no system encodes it.
    Unencodable,
}

/// The bounds of a `range` at a date: E ≤ `birth_date` ≤ C. `None` for a range without that
/// bound: the system then takes its widest value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// E, the earliest birth date.
    pub earliest: Option<Bound>,
    /// C, the latest birth date.
    pub cutoff: Option<Bound>,
}

/// A bound more than `u64::MAX` years before the proof date: no system encodes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Unencodable;

impl Bounds {
    /// The bounds of an option without `age_check`: none.
    pub const WIDEST: Self = Self {
        earliest: None,
        cutoff: None,
    };

    /// E and C as calendar dates; `None` for a range without that bound.
    ///
    /// # Errors
    ///
    /// [`Unencodable`] for a bound no system encodes.
    pub fn dates(&self) -> Result<(Option<Date>, Option<Date>), Unencodable> {
        let date = |bound: Option<Bound>| match bound {
            None => Ok(None),
            Some(Bound::Date(d)) => Ok(Some(d)),
            Some(Bound::Unencodable) => Err(Unencodable),
        };
        Ok((date(self.earliest)?, date(self.cutoff)?))
    }

    /// Whether `birth_date` lies in `[E, C]`.
    pub fn holds(&self, birth_date: Date) -> bool {
        let above = match self.earliest {
            None | Some(Bound::Unencodable) => true,
            Some(Bound::Date(e)) => e <= birth_date,
        };
        let below = match self.cutoff {
            None => true,
            Some(Bound::Unencodable) => false,
            Some(Bound::Date(c)) => birth_date <= c,
        };
        above && below
    }

    /// Whether every bound present lies within `[min, max]`.
    pub fn within(&self, min: Date, max: Date) -> bool {
        [self.earliest, self.cutoff]
            .iter()
            .flatten()
            .all(|b| match b {
                Bound::Date(d) => min <= *d && *d <= max,
                Bound::Unencodable => false,
            })
    }
}

/// D minus N years: the month and day of D in year `D.year - N`. When that is 29 February of a
/// common year, it is no calendar date; it lies between 28 February and 1 March.
enum YearsBefore {
    Date(Date),
    LeapDayOf(i64),
}

fn years_before(d: Date, n: u64) -> Option<YearsBefore> {
    let year = d.year().checked_sub(i64::try_from(n).ok()?)?;
    if d.month() == 2 && d.day() == 29 && !is_leap(year) {
        return Some(YearsBefore::LeapDayOf(year));
    }
    Date::new(year, d.month(), d.day()).map(YearsBefore::Date)
}

/// C: the latest calendar date on or before D minus A years.
fn cutoff(d: Date, a: &Age) -> Bound {
    match a.years().and_then(|a| years_before(d, a)) {
        Some(YearsBefore::Date(date)) => Bound::Date(date),
        Some(YearsBefore::LeapDayOf(year)) => {
            Date::new(year, 2, 28).map_or(Bound::Unencodable, Bound::Date)
        }
        None => Bound::Unencodable,
    }
}

/// E: the earliest calendar date after D minus (B + 1) years.
fn earliest(d: Date, b: &Age) -> Bound {
    let n = b.years().and_then(|b| b.checked_add(1));
    match n.and_then(|n| years_before(d, n)) {
        Some(YearsBefore::Date(date)) => Bound::Date(date.next()),
        Some(YearsBefore::LeapDayOf(year)) => {
            Date::new(year, 3, 1).map_or(Bound::Unencodable, Bound::Date)
        }
        None => Bound::Unencodable,
    }
}
