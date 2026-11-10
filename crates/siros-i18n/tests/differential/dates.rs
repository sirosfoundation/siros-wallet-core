//! `:siros:date`, `:siros:time` and `:siros:datetime` at every length, for each day of 2000
//! to 2030 at 00:00, 09:05, 12:00 and 23:59, against ICU4X's `DateTimeFormatter` with the field
//! set each length stands for:
//!
//! | length | date | time | date and time |
//! | :-- | :-- | :-- | :-- |
//! | short | `YMD` short | `T` short, minutes | `YMDT` short, minutes |
//! | medium | `YMD` medium | `T` medium | `YMDT` medium |
//! | long | `YMD` long | `T` medium, the short offset when given | `YMDT` long, likewise |
//! | full | `YMDE` long | `T` medium, the long offset when given | `YMDET` long, likewise |
//!
//! Offsets are compared on the first day of each month. Dates and dates with times at each
//! length are also compared on 4 March and 31 December of each year from 0 to 3000 and of 9999.

use icu_calendar::{Date as IsoDate, Iso};
use icu_datetime::DateTimeFormatter;
use icu_datetime::fieldsets::{self, zone};
use icu_datetime::options::TimePrecision;
use icu_locale_core::Locale;
use icu_time::zone::models::Base;
use icu_time::zone::{TimeZone, UtcOffset};
use icu_time::{DateTime as IcuDateTime, Time as IsoTime, TimeZoneInfo, ZonedDateTime};
use siros_i18n::Context;
use siros_syntax::{Date, DateTime, Offset, OffsetTime, Time};

use crate::{Differences, LANGUAGES, context, plain};

/// Each value is an argument's text: its type's ISO 8601 literal.
#[derive(Debug, siros_i18n::Message)]
enum Probe {
    #[message(id = "date_short")]
    DateShort { d: Date },
    #[message(id = "date_medium")]
    DateMedium { d: Date },
    #[message(id = "date_long")]
    DateLong { d: Date },
    #[message(id = "date_full")]
    DateFull { d: Date },
    #[message(id = "time_short")]
    TimeShort { t: OffsetTime },
    #[message(id = "time_medium")]
    TimeMedium { t: OffsetTime },
    #[message(id = "time_long")]
    TimeLong { t: OffsetTime },
    #[message(id = "time_full")]
    TimeFull { t: OffsetTime },
    #[message(id = "both_short")]
    BothShort { d: DateTime },
    #[message(id = "both_medium")]
    BothMedium { d: DateTime },
    #[message(id = "both_long")]
    BothLong { d: DateTime },
    #[message(id = "both_full")]
    BothFull { d: DateTime },
}

const MESSAGES: &str = "\
[probe]
date_short = {$d :siros:date length=short}
date_medium = {$d :siros:date length=medium}
date_long = {$d :siros:date length=long}
date_full = {$d :siros:date length=full}
time_short = {$t :siros:time length=short}
time_medium = {$t :siros:time length=medium}
time_long = {$t :siros:time length=long}
time_full = {$t :siros:time length=full}
both_short = {$d :siros:datetime length=short}
both_medium = {$d :siros:datetime length=medium}
both_long = {$d :siros:datetime length=long}
both_full = {$d :siros:datetime length=full}";

const TIMES: [(u8, u8); 4] = [(0, 0), (9, 5), (12, 0), (23, 59)];

/// Offsets compared, in minutes.
const OFFSETS: [i16; 4] = [60, -330, 0, 345];

type Plain = Box<dyn Fn(&IcuDateTime<Iso>) -> String>;
type Zoned = Box<dyn Fn(&ZonedDateTime<Iso, TimeZoneInfo<Base>>) -> String>;

macro_rules! icu {
    ($locale:expr, $set:expr, $input:ty) => {{
        let formatter = DateTimeFormatter::try_new($locale.into(), $set).expect("data");
        Box::new(move |input: &$input| formatter.format(input).to_string())
    }};
}

/// ICU4X's formatters of one language, by length: short, medium, long, full.
struct Theirs {
    date: [Plain; 4],
    time: [Plain; 4],
    both: [Plain; 4],
    time_zoned: [Zoned; 2],
    both_zoned: [Zoned; 2],
}

impl Theirs {
    fn of(locale: &Locale) -> Self {
        let minute = TimePrecision::Minute;
        Self {
            date: [
                icu!(locale, fieldsets::YMD::short(), IcuDateTime<Iso>),
                icu!(locale, fieldsets::YMD::medium(), IcuDateTime<Iso>),
                icu!(locale, fieldsets::YMD::long(), IcuDateTime<Iso>),
                icu!(locale, fieldsets::YMDE::long(), IcuDateTime<Iso>),
            ],
            time: [
                icu!(
                    locale,
                    fieldsets::T::short().with_time_precision(minute),
                    IcuDateTime<Iso>
                ),
                icu!(locale, fieldsets::T::medium(), IcuDateTime<Iso>),
                icu!(locale, fieldsets::T::medium(), IcuDateTime<Iso>),
                icu!(locale, fieldsets::T::medium(), IcuDateTime<Iso>),
            ],
            both: [
                icu!(
                    locale,
                    fieldsets::YMDT::short().with_time_precision(minute),
                    IcuDateTime<Iso>
                ),
                icu!(locale, fieldsets::YMDT::medium(), IcuDateTime<Iso>),
                icu!(locale, fieldsets::YMDT::long(), IcuDateTime<Iso>),
                icu!(locale, fieldsets::YMDET::long(), IcuDateTime<Iso>),
            ],
            time_zoned: [
                icu!(locale, fieldsets::T::medium().with_zone(zone::LocalizedOffsetShort), ZonedDateTime<Iso, TimeZoneInfo<Base>>),
                icu!(locale, fieldsets::T::medium().with_zone(zone::LocalizedOffsetLong), ZonedDateTime<Iso, TimeZoneInfo<Base>>),
            ],
            both_zoned: [
                icu!(locale, fieldsets::YMDT::long().with_zone(zone::LocalizedOffsetShort), ZonedDateTime<Iso, TimeZoneInfo<Base>>),
                icu!(locale, fieldsets::YMDET::long().with_zone(zone::LocalizedOffsetLong), ZonedDateTime<Iso, TimeZoneInfo<Base>>),
            ],
        }
    }
}

/// Every day of 2000 to 2030.
fn days() -> Vec<Date> {
    (2000..=2030u16)
        .flat_map(|year| {
            (1..=12u8).flat_map(move |month| {
                (1..=31u8).filter_map(move |day| Date::new(year, month, day))
            })
        })
        .collect()
}

fn icu_at(date: Date, hour: u8, minute: u8) -> IcuDateTime<Iso> {
    IcuDateTime {
        date: IsoDate::try_new_iso(i32::from(date.year()), date.month(), date.day())
            .expect("a date"),
        time: IsoTime::try_new(hour, minute, 0, 0).expect("a time"),
    }
}

fn time(hour: u8, minute: u8) -> Time {
    Time::new(hour, minute, None).expect("a time")
}

#[test]
#[ignore = "the per-merge tier: CI's per-merge job runs it with --ignored"]
fn dates_and_times_equal_icu4x() {
    let days = days();
    let mut differences = Differences::default();
    for language in LANGUAGES {
        let context = context(language, MESSAGES);
        let locale: Locale = language.parse().expect("a locale");
        let theirs = Theirs::of(&locale);
        let lengths = ["short", "medium", "long", "full"];
        for &(hour, minute) in &TIMES {
            let t = OffsetTime::new(time(hour, minute), None);
            let ours = [
                Probe::TimeShort { t },
                Probe::TimeMedium { t },
                Probe::TimeLong { t },
                Probe::TimeFull { t },
            ];
            let input = icu_at(Date::new(2000, 1, 1).expect("a date"), hour, minute);
            for ((message, theirs), length) in ours.iter().zip(&theirs.time).zip(lengths) {
                let at = format!("{language} time {length} {hour:02}:{minute:02}");
                differences.check(&at, &plain(&context, message), &theirs(&input));
            }
        }
        for &d in &days {
            let midnight = icu_at(d, 0, 0);
            let ours = [
                Probe::DateShort { d },
                Probe::DateMedium { d },
                Probe::DateLong { d },
                Probe::DateFull { d },
            ];
            for ((message, theirs), length) in ours.iter().zip(&theirs.date).zip(lengths) {
                let at = format!("{language} date {length} {d:?}");
                differences.check(&at, &plain(&context, message), &theirs(&midnight));
            }
            for &(hour, minute) in &TIMES {
                let both = DateTime::new(d, time(hour, minute), None);
                let input = icu_at(d, hour, minute);
                let ours = [
                    Probe::BothShort { d: both },
                    Probe::BothMedium { d: both },
                    Probe::BothLong { d: both },
                    Probe::BothFull { d: both },
                ];
                for ((message, theirs), length) in ours.iter().zip(&theirs.both).zip(lengths) {
                    let at = format!("{language} datetime {length} {d:?} {hour:02}:{minute:02}");
                    differences.check(&at, &plain(&context, message), &theirs(&input));
                }
            }
            if d.day() == 1 {
                zoned(&context, &theirs, language, d, &mut differences);
            }
        }
    }
    differences.assert_none("dates and times");
}

/// The long and full lengths of a time and a date and time at each offset.
fn zoned(
    context: &Context,
    theirs: &Theirs,
    language: &str,
    d: Date,
    differences: &mut Differences,
) {
    for minutes in OFFSETS {
        let offset = Offset::new(minutes).expect("an offset");
        let at = icu_at(d, 9, 5);
        let zone = TimeZone::UNKNOWN.with_offset(Some(
            UtcOffset::try_from_seconds(i32::from(minutes) * 60).expect("an offset"),
        ));
        let input = ZonedDateTime {
            date: at.date,
            time: at.time,
            zone,
        };
        let t = OffsetTime::new(time(9, 5), Some(offset));
        let both = DateTime::new(d, time(9, 5), Some(offset));
        let ours = [
            Probe::TimeLong { t },
            Probe::TimeFull { t },
            Probe::BothLong { d: both },
            Probe::BothFull { d: both },
        ];
        let theirs = theirs.time_zoned.iter().chain(&theirs.both_zoned);
        for (message, theirs) in ours.iter().zip(theirs) {
            let at = format!("{language} {message:?}");
            differences.check(&at, &plain(context, message), &theirs(&input));
        }
    }
}

/// Years where ICU4X writes a two-digit year in full (1000 to 1949 and from 2050) or adds the
/// era (to 999), each on 4 March and 31 December, and 1 January of year 0, whose weekday counts
/// from the year before.
fn years() -> Vec<Date> {
    (0..=3000u16)
        .chain([9999])
        .flat_map(|year| [Date::new(year, 3, 4), Date::new(year, 12, 31)])
        .chain([Date::new(0, 1, 1)])
        .flatten()
        .collect()
}

/// Whether ICU4X's text is the one cell where its pattern is CLDR 49's German `GyMMMMEd`,
/// `d MMMM Y G, E`, whose week-based year `Y` ICU4X 2.4 writes as the letter: the full length
/// before year 1000. `:siros:date` writes the full pattern with CLDR's `Gy`.
fn week_year_cell(language: &str, length: &str, year: u16, theirs: &str) -> bool {
    language == "de" && length == "full" && year < 1000 && theirs.contains(" Y ")
}

#[test]
#[ignore = "the per-merge tier: CI's per-merge job runs it with --ignored"]
fn years_equal_icu4x() {
    let mut differences = Differences::default();
    for language in LANGUAGES {
        let context = context(language, MESSAGES);
        let theirs = Theirs::of(&language.parse().expect("a locale"));
        let lengths = ["short", "medium", "long", "full"];
        for d in years() {
            let both = DateTime::new(d, time(9, 5), None);
            let ours = [
                Probe::DateShort { d },
                Probe::DateMedium { d },
                Probe::DateLong { d },
                Probe::DateFull { d },
                Probe::BothShort { d: both },
                Probe::BothMedium { d: both },
                Probe::BothLong { d: both },
                Probe::BothFull { d: both },
            ];
            let input = icu_at(d, 9, 5);
            let theirs = theirs.date.iter().chain(&theirs.both);
            for ((message, theirs), length) in ours.iter().zip(theirs).zip(lengths.iter().cycle()) {
                let theirs = theirs(&input);
                if !week_year_cell(language, length, d.year(), &theirs) {
                    let at = format!("{language} {length} {message:?}");
                    differences.check(&at, &plain(&context, message), &theirs);
                }
            }
        }
    }
    differences.assert_none("years");
}
