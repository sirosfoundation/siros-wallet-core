//! Numbers and amounts: the cardinal and ordinal categories and the texts of the probe's
//! 153 values, and amounts in every ISO 4217 currency by symbol, narrow symbol, code and name.
//! Each value is an argument's text, the literal ICU4X parses.

use fixed_decimal::Decimal as Fixed;
use icu_decimal::DecimalFormatter;
use icu_experimental::dimension::currency::formatter::CurrencyFormatter;
use icu_locale_core::Locale;
use icu_locale_core::preferences::extensions::unicode::keywords::CurrencyType;
use icu_plurals::{PluralCategory, PluralRules};
use siros_i18n::ResolveError;
use siros_syntax::Currency;
use writeable::Writeable as _;

use crate::{Differences, LANGUAGES, context, plain};

#[derive(siros_i18n::Message)]
enum Probe<'a> {
    #[message(id = "cardinal")]
    Cardinal { n: &'a str },
    #[message(id = "ordinal")]
    Ordinal { n: &'a str },
    #[message(id = "number")]
    Number { n: &'a str },
    #[message(id = "symbol")]
    Symbol { amount: &'a str, currency: &'a str },
    #[message(id = "narrow")]
    Narrow { amount: &'a str, currency: &'a str },
    #[message(id = "code")]
    Code { amount: &'a str, currency: &'a str },
    #[message(id = "name")]
    Name { amount: &'a str, currency: &'a str },
}

const MESSAGES: &str = "\
[probe]
cardinal = .input {$n :number} .match $n zero {{zero}} one {{one}} two {{two}} few {{few}} many {{many}} * {{other}}
ordinal = .input {$n :number select=ordinal} .match $n zero {{zero}} one {{one}} two {{two}} few {{few}} many {{many}} * {{other}}
number = {$n :number}
symbol = {$amount :currency currency=$currency}
narrow = {$amount :currency currency=$currency currencyDisplay=narrowSymbol}
code = {$amount :currency currency=$currency currencyDisplay=code}
name = {$amount :currency currency=$currency currencyDisplay=name}";

/// The probe's 153 values: 0 to 120, then integers, decimals, negatives and large numbers, and
/// decimals written with trailing zeros or more than three fraction digits, which show as
/// written.
fn values() -> Vec<String> {
    let mut values: Vec<String> = (0..=120).map(|n| n.to_string()).collect();
    values.extend(
        [
            "200",
            "1000",
            "1001",
            "10000",
            "100000",
            "1000000",
            "1000001",
            "0.5",
            "1.5",
            "2.5",
            "0.1",
            "1.1",
            "2.1",
            "3.25",
            "5.75",
            "21.5",
            "101.1",
            "1234.567",
            "-1",
            "-2",
            "-1234.5",
            "0.001",
            "12345.678",
            "999999.5",
            "1.0",
            "1.50",
            "-0.50",
            "0.10",
            "100.000",
            "0.1234",
            "2.00005",
            "1234.5678",
        ]
        .map(str::to_owned),
    );
    values
}

fn keyword(category: PluralCategory) -> &'static str {
    match category {
        PluralCategory::Zero => "zero",
        PluralCategory::One => "one",
        PluralCategory::Two => "two",
        PluralCategory::Few => "few",
        PluralCategory::Many => "many",
        PluralCategory::Other => "other",
    }
}

#[test]
#[ignore = "the per-merge tier: CI's per-merge job runs it with --ignored"]
fn plural_categories_and_number_texts_equal_icu4x() {
    let values = values();
    let mut differences = Differences::default();
    for language in LANGUAGES {
        let context = context(language, MESSAGES);
        let locale: Locale = language.parse().expect("a locale");
        let cardinal = PluralRules::try_new_cardinal((&locale).into()).expect("rules");
        let ordinal = PluralRules::try_new_ordinal((&locale).into()).expect("rules");
        let numbers =
            DecimalFormatter::try_new((&locale).into(), Default::default()).expect("a formatter");
        for text in &values {
            let fixed = Fixed::try_from_str(text).expect("a decimal");
            let n = text.as_str();
            let at = format!("{language} {text}");
            let ours = plain(&context, &Probe::Cardinal { n });
            differences.check(
                &format!("{at} cardinal"),
                &ours,
                keyword(cardinal.category_for(&fixed)),
            );
            if !text.contains('.') && !text.starts_with('-') {
                let ours = plain(&context, &Probe::Ordinal { n });
                differences.check(
                    &format!("{at} ordinal"),
                    &ours,
                    keyword(ordinal.category_for(&fixed)),
                );
            }
            let ours = plain(&context, &Probe::Number { n });
            let theirs = numbers.format(&fixed).write_to_string().into_owned();
            differences.check(&format!("{at} text"), &ours, &theirs);
        }
    }
    differences.assert_none("numbers");
}

/// An argument's literal bounds the text it formats: ICU4X refuses a digit whose power of ten
/// passes `i16`, and the context refuses the operand where ICU4X does and formats it as ICU4X
/// does inside. An argument such as `1e999999999` would otherwise write a billion digits.
#[test]
fn literal_bounds_equal_icu4x() {
    let context = context("en", MESSAGES);
    let locale: Locale = "en".parse().expect("a locale");
    let numbers =
        DecimalFormatter::try_new((&locale).into(), Default::default()).expect("a formatter");
    let texts = [
        "1e32767",
        "1e32768",
        "12e32766",
        "12e32767",
        "1e-32768",
        "1e-32769",
        "0.1e-32767",
        "0.1e-32768",
        "1e999999999",
    ];
    for text in texts {
        match (
            Fixed::try_from_str(text),
            context.resolve(&Probe::Number { n: text }),
        ) {
            (Ok(fixed), Ok(ours)) => {
                let theirs = numbers.format(&fixed).write_to_string().into_owned();
                assert_eq!(ours.to_string(), theirs, "{text}");
            }
            (Err(_), Err(ResolveError::Operand { function, .. })) => {
                assert_eq!(function, "number", "{text}");
            }
            (theirs, ours) => panic!("{text}: ICU4X {:?}, ours {:?}", theirs.is_ok(), ours),
        }
    }
}

/// The code of every currency ISO 4217's table lists.
fn currencies() -> Vec<String> {
    let letters = || b'A'..=b'Z';
    letters()
        .flat_map(|a| letters().flat_map(move |b| letters().map(move |c| [a, b, c])))
        .map(|code| String::from_utf8(code.to_vec()).expect("ASCII"))
        .filter(|code| Currency::parse(code).is_ok())
        .collect()
}

/// The cells where CLDR 49 sets a symbol equal to the currency's code: ICU4X 2.4's data
/// generator keeps a symbol only when it differs from the code (icu_provider_source 2.4.0,
/// `currency/symbols.rs`), so ICU4X falls back to the root locale's symbol, here given. The
/// currency section keeps CLDR's: the check replaces root's symbol in ICU4X's text with the code.
const CODE_SYMBOLS: [(&str, &str, &str, &str); 4] = [
    ("de", "PHP", "symbol", "\u{20b1}"),
    ("de", "SYP", "narrow", "\u{a3}"),
    ("de", "XXX", "symbol", "\u{a4}"),
    ("de", "XXX", "narrow", "\u{a4}"),
];

/// ICU4X's text, with root's symbol replaced by the code where CLDR sets the code.
fn cldr_symbol(language: &str, code: &str, display: &str, theirs: String) -> String {
    let found = CODE_SYMBOLS
        .iter()
        .find(|cell| (cell.0, cell.1, cell.2) == (language, code, display));
    match found {
        Some((.., root)) => theirs.replace(root, code),
        None => theirs,
    }
}

#[test]
#[ignore = "the per-merge tier: CI's per-merge job runs it with --ignored"]
fn amounts_in_every_currency_equal_icu4x() {
    let currencies = currencies();
    let amounts = ["1234567.891", "-1234.5", "0", "1", "2.5", "0.005"];
    let mut differences = Differences::default();
    for language in LANGUAGES {
        let context = context(language, MESSAGES);
        let locale: Locale = language.parse().expect("a locale");
        for code in &currencies {
            let kind = CurrencyType::try_from_str(&code.to_ascii_lowercase()).expect("a code");
            let prefs = (&locale).into();
            let symbol =
                CurrencyFormatter::try_new_symbol(prefs, kind, Default::default()).expect("data");
            let narrow = CurrencyFormatter::try_new_symbol_narrow(prefs, kind, Default::default())
                .expect("data");
            let coded =
                CurrencyFormatter::try_new_code(prefs, kind, Default::default()).expect("data");
            let named = CurrencyFormatter::try_new_name(prefs, kind).expect("data");
            for amount in amounts {
                let currency = code.as_str();
                let fixed = Fixed::try_from_str(amount).expect("a decimal");
                let at = format!("{language} {code} {amount}");
                let pairs = [
                    (
                        "symbol",
                        Probe::Symbol { amount, currency },
                        symbol
                            .format_fixed_decimal(&fixed)
                            .write_to_string()
                            .into_owned(),
                    ),
                    (
                        "narrow",
                        Probe::Narrow { amount, currency },
                        narrow
                            .format_fixed_decimal(&fixed)
                            .write_to_string()
                            .into_owned(),
                    ),
                    (
                        "code",
                        Probe::Code { amount, currency },
                        coded
                            .format_fixed_decimal(&fixed)
                            .write_to_string()
                            .into_owned(),
                    ),
                    (
                        "name",
                        Probe::Name { amount, currency },
                        named
                            .format_fixed_decimal(&fixed)
                            .write_to_string()
                            .into_owned(),
                    ),
                ];
                for (display, message, theirs) in pairs {
                    let theirs = cldr_symbol(language, code, display, theirs);
                    differences.check(
                        &format!("{at} {display}"),
                        &plain(&context, &message),
                        &theirs,
                    );
                }
            }
        }
    }
    differences.assert_none("currencies");
}
