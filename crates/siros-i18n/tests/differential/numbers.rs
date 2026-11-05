//! Numbers and amounts: the cardinal and ordinal categories and the texts of the probe's
//! 153 values, and amounts in every ISO 4217 currency by symbol, narrow symbol, code and name.

use fixed_decimal::Decimal as Fixed;
use icu_decimal::DecimalFormatter;
use icu_experimental::dimension::currency::formatter::CurrencyFormatter;
use icu_locale_core::Locale;
use icu_locale_core::preferences::extensions::unicode::keywords::CurrencyType;
use icu_plurals::{PluralCategory, PluralRules};
use siros_explain::{Amount, Currency, Decimal, Explain, Text, Value};
use writeable::Writeable as _;

use crate::{Differences, SHIPPED, cldr, module, plain, renderer};

#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "probe")]
enum Probe {
    #[error("{n:?}")]
    Cardinal { n: Decimal },
    #[error("{n:?}")]
    Ordinal { n: Decimal },
    #[error("{amount:?}")]
    Symbol { amount: Amount },
    #[error("{amount:?}")]
    Narrow { amount: Amount },
    #[error("{amount:?}")]
    Code { amount: Amount },
    #[error("{amount:?}")]
    Name { amount: Amount },
}

const MESSAGES: &str = "\
[probe]
cardinal = .input {$n :number} .match $n zero {{zero}} one {{one}} two {{two}} few {{few}} many {{many}} * {{other}}
ordinal = .input {$n :number select=ordinal} .match $n zero {{zero}} one {{one}} two {{two}} few {{few}} many {{many}} * {{other}}
symbol = {$amount :currency}
narrow = {$amount :currency currencyDisplay=narrowSymbol}
code = {$amount :currency currencyDisplay=code}
name = {$amount :currency currencyDisplay=name}";

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

/// The decimal a text writes.
fn decimal(text: &str) -> Decimal {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let units: i128 = format!("{whole}{fraction}").parse().expect("digits");
    Decimal::new(units, u8::try_from(fraction.len()).expect("a scale")).expect("a decimal")
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
    let formats = cldr::formats(&[]);
    let values = values();
    let mut differences = Differences::default();
    for language in SHIPPED {
        let module = module::<Probe>(language, MESSAGES);
        let renderer = renderer(&module, language, &formats);
        let locale: Locale = language.parse().expect("a locale");
        let cardinal = PluralRules::try_new_cardinal((&locale).into()).expect("rules");
        let ordinal = PluralRules::try_new_ordinal((&locale).into()).expect("rules");
        let numbers =
            DecimalFormatter::try_new((&locale).into(), Default::default()).expect("a formatter");
        for text in &values {
            let fixed = Fixed::try_from_str(text).expect("a decimal");
            let n = decimal(text);
            let at = format!("{language} {text}");
            let ours = plain(&renderer, &Probe::Cardinal { n });
            differences.check(
                &format!("{at} cardinal"),
                &ours,
                keyword(cardinal.category_for(&fixed)),
            );
            if !text.contains('.') && !text.starts_with('-') {
                let ours = plain(&renderer, &Probe::Ordinal { n });
                differences.check(
                    &format!("{at} ordinal"),
                    &ours,
                    keyword(ordinal.category_for(&fixed)),
                );
            }
            let ours = renderer
                .plain(&Text::Value(Value::Decimal(n)))
                .expect("renders");
            let theirs = numbers.format(&fixed).write_to_string().into_owned();
            differences.check(&format!("{at} text"), &ours, &theirs);
        }
    }
    differences.assert_none("numbers");
}

/// Every currency ISO 4217's table lists, by its code's letters.
fn currencies() -> Vec<(Currency, String)> {
    let letters = || b'A'..=b'Z';
    letters()
        .flat_map(|a| letters().flat_map(move |b| letters().map(move |c| [a, b, c])))
        .filter_map(|code| {
            let code = String::from_utf8(code.to_vec()).expect("ASCII");
            Currency::from_code(&code).map(|currency| (currency, code))
        })
        .collect()
}

/// The cells where CLDR 49 sets a symbol equal to the currency's code: ICU4X 2.4's data
/// generator keeps a symbol only when it differs from the code (icu_provider_source 2.4.0,
/// `currency/symbols.rs`), so ICU4X falls back to the root locale's symbol, here given. The
/// module keeps CLDR's: the check replaces root's symbol in ICU4X's text with the code.
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
    let formats = cldr::formats(&[]);
    let currencies = currencies();
    let amounts = ["1234567.891", "-1234.5", "0", "1", "2.5", "0.005"];
    let mut differences = Differences::default();
    for language in SHIPPED {
        let module = module::<Probe>(language, MESSAGES);
        let renderer = renderer(&module, language, &formats);
        let locale: Locale = language.parse().expect("a locale");
        for (currency, code) in &currencies {
            let kind = CurrencyType::try_from_str(&code.to_ascii_lowercase()).expect("a code");
            let prefs = (&locale).into();
            let symbol =
                CurrencyFormatter::try_new_symbol(prefs, kind, Default::default()).expect("data");
            let narrow = CurrencyFormatter::try_new_symbol_narrow(prefs, kind, Default::default())
                .expect("data");
            let coded =
                CurrencyFormatter::try_new_code(prefs, kind, Default::default()).expect("data");
            let named = CurrencyFormatter::try_new_name(prefs, kind).expect("data");
            for text in amounts {
                let amount = Amount::new(decimal(text), *currency);
                let fixed = Fixed::try_from_str(text).expect("a decimal");
                let at = format!("{language} {code} {text}");
                let pairs = [
                    (
                        "symbol",
                        Probe::Symbol { amount },
                        symbol
                            .format_fixed_decimal(&fixed)
                            .write_to_string()
                            .into_owned(),
                    ),
                    (
                        "narrow",
                        Probe::Narrow { amount },
                        narrow
                            .format_fixed_decimal(&fixed)
                            .write_to_string()
                            .into_owned(),
                    ),
                    (
                        "code",
                        Probe::Code { amount },
                        coded
                            .format_fixed_decimal(&fixed)
                            .write_to_string()
                            .into_owned(),
                    ),
                    (
                        "name",
                        Probe::Name { amount },
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
                        &plain(&renderer, &message),
                        &theirs,
                    );
                }
                let bare = renderer
                    .plain(&Text::Value(Value::Amount(amount)))
                    .expect("renders");
                let theirs = symbol
                    .format_fixed_decimal(&fixed)
                    .write_to_string()
                    .into_owned();
                let theirs = cldr_symbol(language, code, "symbol", theirs);
                differences.check(&format!("{at} bare"), &bare, &theirs);
            }
        }
    }
    differences.assert_none("currencies");
}
