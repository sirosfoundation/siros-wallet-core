//! Each type's literal, against the forms the crate states: a value writes its literal and the
//! literal parses back to the value; a text outside the form is refused at the byte where it leaves
//! the form. Then where RFC 3339 places a leap second, and a key given twice.

use siros_syntax::{
    Amount, Count, Currency, Date, DateTime, Decimal, Entry, Fraction, Keyed, Malformed, Offset,
    OffsetTime, Repeated, Second, Time,
};

/// A value of one of the crate's literal types.
#[derive(Debug, PartialEq)]
enum Literal {
    Count(Count),
    Decimal(Decimal),
    Currency(Currency),
    Amount(Amount),
    Date(Date),
    Time(Time),
    Offset(Offset),
    OffsetTime(OffsetTime),
    DateTime(DateTime),
}

impl Literal {
    /// Its type's name, which a refusal gives.
    fn of(&self) -> &'static str {
        match self {
            Self::Count(_) => "Count",
            Self::Decimal(_) => "Decimal",
            Self::Currency(_) => "Currency",
            Self::Amount(_) => "Amount",
            Self::Date(_) => "Date",
            Self::Time(_) => "Time",
            Self::Offset(_) => "Offset",
            Self::OffsetTime(_) => "OffsetTime",
            Self::DateTime(_) => "DateTime",
        }
    }

    /// Its literal.
    fn literal(&self) -> String {
        match self {
            Self::Count(value) => value.to_string(),
            Self::Decimal(value) => value.to_string(),
            Self::Currency(value) => value.to_string(),
            Self::Amount(value) => value.to_string(),
            Self::Date(value) => value.to_string(),
            Self::Time(value) => value.to_string(),
            Self::Offset(value) => value.to_string(),
            Self::OffsetTime(value) => value.to_string(),
            Self::DateTime(value) => value.to_string(),
        }
    }
}

/// `text` parsed as a literal of the type `of`.
fn parse(of: &str, text: &str) -> Result<Literal, Malformed> {
    match of {
        "Count" => Count::parse(text).map(Literal::Count),
        "Decimal" => Decimal::parse(text).map(Literal::Decimal),
        "Currency" => Currency::parse(text).map(Literal::Currency),
        "Amount" => Amount::parse(text).map(Literal::Amount),
        "Date" => Date::parse(text).map(Literal::Date),
        "Time" => Time::parse(text).map(Literal::Time),
        "Offset" => Offset::parse(text).map(Literal::Offset),
        "OffsetTime" => OffsetTime::parse(text).map(Literal::OffsetTime),
        "DateTime" => DateTime::parse(text).map(Literal::DateTime),
        _ => panic!("no literal type {of}"),
    }
}

fn decimal(units: i128, scale: u8) -> Decimal {
    Decimal::new(units, scale).expect("a decimal")
}

fn currency(code: &str) -> Currency {
    Currency::parse(code).expect("an ISO 4217 code")
}

fn date(year: u16, month: u8, day: u8) -> Date {
    Date::new(year, month, day).expect("a calendar date")
}

fn time(hour: u8, minute: u8, second: Option<(u8, u32, u8)>) -> Time {
    let second = second.map(|(whole, nanos, digits)| {
        Second::new(whole, Fraction::new(nanos, digits).expect("a fraction")).expect("a second")
    });
    Time::new(hour, minute, second).expect("a time")
}

fn offset(minutes: i16) -> Offset {
    Offset::new(minutes).expect("an offset")
}

/// Every value writes its literal, which parses back to it; every refused text is refused where it
/// leaves the form. The literals are the forms the crate states, the values its constructors make.
#[test]
fn a_value_is_its_literal() {
    let writes = [
        ("0", Literal::Count(Count::of(0))),
        ("1234", Literal::Count(Count::of(1234))),
        ("18446744073709551615", Literal::Count(Count::of(u64::MAX))),
        ("0", Literal::Decimal(decimal(0, 0))),
        ("0.00", Literal::Decimal(decimal(0, 2))),
        ("1234.5", Literal::Decimal(decimal(12345, 1))),
        ("42.50", Literal::Decimal(decimal(4250, 2))),
        ("-0.05", Literal::Decimal(decimal(-5, 2))),
        (
            "170141183460469231731687303715884105727",
            Literal::Decimal(decimal(i128::MAX, 0)),
        ),
        (
            "-170141183460469231731687303715884105728",
            Literal::Decimal(decimal(i128::MIN, 0)),
        ),
        (
            "-1.70141183460469231731687303715884105728",
            Literal::Decimal(decimal(i128::MIN, 38)),
        ),
        ("EUR", Literal::Currency(currency("EUR"))),
        (
            "42.50 EUR",
            Literal::Amount(Amount::new(decimal(4250, 2), currency("EUR"))),
        ),
        (
            "-3 JPY",
            Literal::Amount(Amount::new(decimal(-3, 0), currency("JPY"))),
        ),
        ("2026-09-02", Literal::Date(date(2026, 9, 2))),
        ("0000-01-01", Literal::Date(date(0, 1, 1))),
        ("9999-12-31", Literal::Date(date(9999, 12, 31))),
        ("2024-02-29", Literal::Date(date(2024, 2, 29))),
        ("2000-02-29", Literal::Date(date(2000, 2, 29))),
        ("00:00", Literal::Time(time(0, 0, None))),
        ("23:59:59", Literal::Time(time(23, 59, Some((59, 0, 0))))),
        (
            "12:30:15.5",
            Literal::Time(time(12, 30, Some((15, 500_000_000, 1)))),
        ),
        ("12:30:00.000", Literal::Time(time(12, 30, Some((0, 0, 3))))),
        (
            "12:30:15.123456789",
            Literal::Time(time(12, 30, Some((15, 123_456_789, 9)))),
        ),
        ("Z", Literal::Offset(offset(0))),
        ("+05:30", Literal::Offset(offset(330))),
        ("-00:01", Literal::Offset(offset(-1))),
        ("-23:59", Literal::Offset(offset(-1439))),
        (
            "12:30",
            Literal::OffsetTime(OffsetTime::new(time(12, 30, None), None)),
        ),
        (
            "12:30:15.5+02:00",
            Literal::OffsetTime(OffsetTime::new(
                time(12, 30, Some((15, 500_000_000, 1))),
                Some(offset(120)),
            )),
        ),
        (
            "2026-09-02T12:30",
            Literal::DateTime(DateTime::new(date(2026, 9, 2), time(12, 30, None), None)),
        ),
        (
            "2026-09-02T12:30:15.5Z",
            Literal::DateTime(DateTime::new(
                date(2026, 9, 2),
                time(12, 30, Some((15, 500_000_000, 1))),
                Some(offset(0)),
            )),
        ),
        (
            "1990-12-31T15:59:60-08:00",
            Literal::DateTime(
                DateTime::leap(date(1990, 12, 31), 15, 59, Fraction::NONE, offset(-480))
                    .expect("RFC 3339 §5.8"),
            ),
        ),
        (
            "1990-12-31T23:59:60.25Z",
            Literal::DateTime(
                DateTime::leap(
                    date(1990, 12, 31),
                    23,
                    59,
                    Fraction::new(250_000_000, 2).expect("a fraction"),
                    offset(0),
                )
                .expect("RFC 3339 §5.8"),
            ),
        ),
    ];
    for (text, value) in writes {
        assert_eq!(value.literal(), text, "{value:?}");
        assert_eq!(parse(value.of(), text), Ok(value), "{text}");
    }

    let long = Count::parse("18446744073709551616").expect("2^64");
    assert_eq!(
        (long.to_string(), long.to_u64(), long > Count::of(u64::MAX)),
        ("18446744073709551616".to_owned(), None, true)
    );

    let refused = [
        ("Count", "", 0),
        ("Count", "007", 1),
        ("Count", "12a", 2),
        ("Count", "-1", 0),
        ("Count", "1 ", 1),
        ("Decimal", "-", 1),
        ("Decimal", "01", 1),
        ("Decimal", "1.", 2),
        ("Decimal", ".5", 0),
        ("Decimal", "1.5.", 3),
        ("Decimal", "1e5", 1),
        ("Decimal", "+1", 0),
        ("Decimal", "-0", 0),
        ("Decimal", "-0.00", 0),
        ("Decimal", "170141183460469231731687303715884105728", 38),
        ("Decimal", "-170141183460469231731687303715884105729", 39),
        ("Decimal", "0.000000000000000000000000000000000000000", 40),
        ("Currency", "eUR", 0),
        ("Currency", "EuR", 1),
        ("Currency", "EU", 2),
        ("Currency", "EURO", 3),
        ("Amount", "42.50EUR", 5),
        ("Amount", "42.50  EUR", 6),
        ("Amount", "42.50 eur", 6),
        ("Amount", "EUR 42.50", 0),
        ("Date", "26-09-02", 2),
        ("Date", "20260902", 4),
        ("Date", "2026-9-02", 6),
        ("Date", "2026-00-01", 5),
        ("Date", "2026-13-01", 5),
        ("Date", "2026-09-00", 8),
        ("Date", "2026-04-31", 8),
        ("Date", "2023-02-29", 8),
        ("Date", "1900-02-29", 8),
        ("Date", "2026-09-02T", 10),
        ("Time", "1:30", 1),
        ("Time", "12", 2),
        ("Time", "24:00", 0),
        ("Time", "12:60", 3),
        ("Time", "12:30:5", 7),
        ("Time", "12:30:60", 6),
        ("Time", "12:30:61", 6),
        ("Time", "12:30:15.", 9),
        ("Time", "12:30:15.1234567890", 18),
        ("Time", "12:30Z", 5),
        ("Offset", "", 0),
        ("Offset", "z", 0),
        ("Offset", "05:30", 0),
        ("Offset", "+00:00", 0),
        ("Offset", "-00:00", 0),
        ("Offset", "+24:00", 1),
        ("Offset", "+0530", 3),
        ("Offset", "+05:60", 4),
        ("OffsetTime", "12:30 Z", 5),
        ("OffsetTime", "12:30+00:00", 5),
        ("OffsetTime", "12:30:15.5+2:00", 12),
        ("DateTime", "2026-09-02", 10),
        ("DateTime", "2026-09-02 12:30", 10),
        ("DateTime", "2026-09-02t12:30", 10),
        ("DateTime", "1990-12-31T23:59:60", 17),
        ("DateTime", "1990-12-30T23:59:60Z", 17),
        ("DateTime", "1990-12-31T23:59:61Z", 17),
        ("DateTime", "2026-09-02T12:30Zx", 17),
    ];
    for (of, text, at) in refused {
        assert_eq!(parse(of, text), Err(Malformed { of, at }), "{of} {text:?}");
    }
}

/// `parse` takes back what `Display` writes, over every offset, every minute of the day, the
/// extreme units at every scale, and every candidate date of years around the Gregorian rules:
/// a date `Date::new` refuses is refused at its month or its day. No date holds a year that four
/// digits cannot write.
#[test]
fn every_value_parses_back() {
    for minutes in -1439..=1439 {
        let value = offset(minutes);
        assert_eq!(Offset::parse(&value.to_string()), Ok(value));
    }
    for hour in 0..24 {
        for minute in 0..60 {
            for value in [
                time(hour, minute, None),
                time(hour, minute, Some((7, 70_000_000, 2))),
            ] {
                assert_eq!(Time::parse(&value.to_string()), Ok(value));
            }
        }
    }
    for scale in 0..=38 {
        for units in [i128::MIN, -1, 0, 1, i128::MAX] {
            let value = decimal(units, scale);
            assert_eq!(Decimal::parse(&value.to_string()), Ok(value));
        }
    }
    assert_eq!(Date::new(10_000, 1, 1), None, "a year past four digits");
    for year in [0, 1, 1900, 2000, 2023, 2024, 9999] {
        for month in 0..=13 {
            for day in 0..=32 {
                let text = format!("{year:04}-{month:02}-{day:02}");
                let expected = match Date::new(year, month, day) {
                    Some(value) => Ok(value),
                    None if (1..=12).contains(&month) => Err(Malformed { of: "Date", at: 8 }),
                    None => Err(Malformed { of: "Date", at: 5 }),
                };
                assert_eq!(Date::parse(&text), expected, "{text}");
            }
        }
    }
}

/// RFC 3339 §5.7 and Appendix D: second 60 only at 23:59:60 UTC on a month's last day, which an
/// offset shifts to its local time; §5.8's two examples hold, and a time of day alone holds none.
#[test]
fn a_leap_second_stands_where_rfc_3339_places_it() {
    let cases = [
        ((1990, 12, 31), 23, 59, 0, true),
        ((1990, 12, 31), 15, 59, -480, true),
        ((1972, 6, 30), 23, 59, 0, true),
        ((1991, 1, 1), 0, 59, 60, true),
        ((0, 1, 1), 0, 0, 1, true),
        ((1990, 12, 30), 0, 59, 60, false),
        ((1990, 12, 30), 23, 59, 0, false),
        ((1990, 12, 31), 23, 58, 0, false),
        ((1990, 12, 31), 23, 59, 60, false),
        ((1990, 12, 31), 15, 59, 0, false),
    ];
    for ((year, month, day), hour, minute, minutes, stands) in cases {
        let leap = DateTime::leap(
            date(year, month, day),
            hour,
            minute,
            Fraction::NONE,
            offset(minutes),
        );
        assert_eq!(
            leap.is_some(),
            stands,
            "{year}-{month}-{day}T{hour}:{minute}:60 at {minutes}"
        );
        if let Some(leap) = leap {
            assert_eq!(
                (leap.second(), leap.offset()),
                (Some(60), Some(offset(minutes)))
            );
        }
    }
    assert_eq!(Second::new(60, Fraction::NONE), None);
}

/// `Keyed` holds each key once: a repeated key is refused with the key, and distinct keys keep
/// their order.
#[test]
fn keyed_refuses_a_repeated_key() {
    let entries = |pairs: &[(&'static str, u8)]| {
        pairs
            .iter()
            .map(|&(key, value)| Entry::new(key, value))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        Keyed::new(entries(&[("en", 1), ("de", 2), ("en", 3)])),
        Err(Repeated { key: "en" })
    );
    let keyed = Keyed::new(entries(&[("en", 1), ("de", 2)])).expect("distinct keys");
    assert_eq!(
        (keyed.get(&"de"), keyed.entries()),
        (Some(&2), &entries(&[("en", 1), ("de", 2)])[..])
    );
}
