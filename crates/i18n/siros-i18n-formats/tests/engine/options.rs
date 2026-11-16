//! An option written as a variable takes the variable's resolved value (spec/formatting.md,
//! "Option Resolution"), whatever binds it: an argument, a literal, or a call a declaration binds.

use siros_i18n::{Bidi, Context};
use siros_syntax::{Amount, Currency, Decimal};

use crate::{Given, cldr};

/// An amount of `text` euros.
fn euros(text: &str) -> Amount {
    Amount::new(
        Decimal::parse(text).expect("a decimal"),
        Currency::parse("EUR").expect("a currency"),
    )
}

/// Each message, the argument `d` it takes when it reads one, and the text MF2 gives it over
/// 12.5 euros or the number 1.5. CLDR's English names 12.50 euros "euros".
const CASES: [(&str, Option<&str>, &str); 7] = [
    (
        "{$a :currency currencyDisplay=$d}",
        Some("name"),
        "12.50 euros",
    ),
    (
        ".local $c = {$d} {{{$a :currency currencyDisplay=$c}}}",
        Some("name"),
        "12.50 euros",
    ),
    (
        ".local $c = {|name|} {{{$a :currency currencyDisplay=$c}}}",
        None,
        "12.50 euros",
    ),
    (
        ".input {$d :string} {{{$a :currency currencyDisplay=$d}}}",
        Some("name"),
        "12.50 euros",
    ),
    (
        ".local $c = {$d :string} {{{$a :currency currencyDisplay=$c}}}",
        Some("name"),
        "12.50 euros",
    ),
    (
        ".local $c = {|name| :string} {{{$a :currency currencyDisplay=$c}}}",
        None,
        "12.50 euros",
    ),
    ("{$x :number minimumFractionDigits=$d}", Some("3"), "1.500"),
];

#[test]
fn an_option_takes_its_variables_value() {
    let mut wrong = Vec::new();
    for (message, d, expected) in CASES {
        let resolved = cldr::context("en", Bidi::None, &format!("m = {message}"))
            .map_err(|error| error.to_string())
            .and_then(|context: Context| {
                let mut given = Given::new("m")
                    .with("a", euros("12.5"))
                    .with("x", Decimal::parse("1.5").expect("a decimal"));
                if let Some(d) = d {
                    given = given.with("d", String::from(d));
                }
                context.resolve(&given).map_err(|error| error.to_string())
            })
            .map(|text| text.to_string());
        if resolved.as_deref() != Ok(expected) {
            wrong.push(format!("{message}: {resolved:?}, MF2 {expected:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}
