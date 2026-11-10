//! An option written as a variable takes the variable's resolved value (spec/formatting.md,
//! "Option Resolution"), whatever binds it: an argument, a literal, or a call a declaration binds.
//! `u:dir` takes a variable whose value names a direction (spec/u-namespace.md).

use siros_i18n::{Bidi, Context};

use crate::{Given, cldr};

/// Each message and its arguments, and the text MF2 gives it. EUR has two fraction digits in
/// English, `:integer` rounds 2.6 to 3, `:offset add=1` makes 4 of 3, and `rtl` isolates its
/// value between U+2067 and U+2069 in a left-to-right message.
const CASES: [(&str, &[(&str, &str)], &str); 12] = [
    (
        "{$a :currency currency=$code}",
        &[("a", "12.5"), ("code", "EUR")],
        "\u{20AC}12.50",
    ),
    (
        ".local $c = {$code} {{{$a :currency currency=$c}}}",
        &[("a", "12.5"), ("code", "EUR")],
        "\u{20AC}12.50",
    ),
    (
        ".local $c = {|EUR|} {{{$a :currency currency=$c}}}",
        &[("a", "12.5")],
        "\u{20AC}12.50",
    ),
    (
        ".input {$code :string} {{{$a :currency currency=$code}}}",
        &[("a", "12.5"), ("code", "EUR")],
        "\u{20AC}12.50",
    ),
    (
        ".local $c = {$code :string} {{{$a :currency currency=$c}}}",
        &[("a", "12.5"), ("code", "EUR")],
        "\u{20AC}12.50",
    ),
    (
        ".local $c = {|EUR| :string} {{{$a :currency currency=$c}}}",
        &[("a", "12.5")],
        "\u{20AC}12.50",
    ),
    (
        ".input {$n :integer} {{{$a :number minimumFractionDigits=$n}}}",
        &[("a", "1.5"), ("n", "2.6")],
        "1.500",
    ),
    (
        ".local $n = {|2.6| :integer} .local $m = {|1| :offset add=$n} \
         {{{$a :number minimumFractionDigits=$m}}}",
        &[("a", "1.5")],
        "1.5000",
    ),
    (
        "{$x :string u:dir=$d}",
        &[("x", "abc"), ("d", "rtl")],
        "\u{2067}abc\u{2069}",
    ),
    (
        ".input {$d} {{{$x :string u:dir=$d}}}",
        &[("x", "abc"), ("d", "rtl")],
        "\u{2067}abc\u{2069}",
    ),
    (
        ".local $d = {|rtl|} {{{$x :string u:dir=$d}}}",
        &[("x", "abc")],
        "\u{2067}abc\u{2069}",
    ),
    (
        ".input {$d :string} {{{$x :string u:dir=$d}}}",
        &[("x", "abc"), ("d", "rtl")],
        "\u{2067}abc\u{2069}",
    ),
];

#[test]
fn an_option_takes_its_variables_value() {
    let mut wrong = Vec::new();
    for (message, args, expected) in CASES {
        let resolved = cldr::context("en", Bidi::Default, &format!("m = {message}"))
            .map_err(|error| error.to_string())
            .and_then(|context: Context| {
                let given = Given {
                    id: "m",
                    args: args
                        .iter()
                        .map(|&(key, text)| (key, text.to_owned()))
                        .collect(),
                };
                context.resolve(&given).map_err(|error| error.to_string())
            })
            .map(|text| text.to_string());
        if resolved.as_deref() != Ok(expected) {
            wrong.push(format!("{message}: {resolved:?}, MF2 {expected:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}
