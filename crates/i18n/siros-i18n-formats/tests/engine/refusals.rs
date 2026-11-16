//! One fixture per refusal of [`Patterns`], each refused for its rule and no other: the format
//! rules of a `[tables]` or `[formats.<name>]` section, and a call's refusals when its module
//! loads and when its message resolves.

use siros_i18n::{Bidi, Context, FormatRule, LoadError, Refusal, ResolveError};
use siros_i18n_formats::Patterns;
use siros_syntax::{Amount, Currency, Decimal, Time};

use crate::{Given, cldr, english};

/// The tables of a module whose formats read numbers, without plural rules.
const TABLES: &str = "[tables]\ndigits = 0123456789\nminus = -\nplus = +\n";

/// A format of numbers whose pattern writes the integer.
const NUMBER: &str = "[formats.number]\nof = number\ndefault = yes\npattern =\n  {int}\n";

/// The standard formatter's context with an English module of each of `modules`' bodies.
fn modules(modules: &[&str]) -> Result<Context, LoadError> {
    let context = Context::builder().formatter(Patterns::standard()).build();
    modules
        .iter()
        .try_fold(context, |context, body| context.module(&english(body)))
}

/// The refusal of `rule` by the section `section`.
fn format(section: &str, rule: FormatRule) -> LoadError {
    LoadError::Format {
        section: section.to_owned(),
        rule,
    }
}

fn key(key: &str) -> String {
    key.to_owned()
}

/// The refusal of a call of `function` in the message `hello`.
fn call(function: &str, refusal: Refusal) -> LoadError {
    LoadError::Call {
        id: key("hello"),
        function: function.to_owned(),
        refusal,
    }
}

fn option(option: &str) -> Refusal {
    Refusal::Option {
        option: option.to_owned(),
    }
}

/// A context of the English formats and a module of `body`.
fn load(body: &str) -> Result<Context, LoadError> {
    cldr::context("en", Bidi::None, body)
}

#[test]
fn each_format_rule_refuses_its_fixture() {
    let number = |settings: &str| format!("{TABLES}\n[formats.number]\n{settings}");
    let cases: Vec<(Result<Context, LoadError>, LoadError)> = vec![
        (
            modules(&[TABLES, TABLES]),
            format("tables", FormatRule::Repeated { key: key("digits") }),
        ),
        (
            modules(&["[tables]\ngrouping = 0"]),
            format("tables", FormatRule::Text { key: key("grouping") }),
        ),
        (
            modules(&[&format!("{TABLES}\n{NUMBER}"), NUMBER]),
            format(
                "formats.number",
                FormatRule::Repeated {
                    key: key("formats.number"),
                },
            ),
        ),
        (
            modules(&[&format!(
                "{TABLES}\n{NUMBER}\n[formats.integer]\nof = number\ndefault = yes\npattern =\n  {{int}}"
            )]),
            format(
                "formats.integer",
                FormatRule::Repeated {
                    key: key("default"),
                },
            ),
        ),
        (
            modules(&[&number("of = number\ncolour = red\npattern =\n  {int}")]),
            format(
                "formats.number",
                FormatRule::Undefined { key: key("colour") },
            ),
        ),
        (
            modules(&[&number("of = number")]),
            format(
                "formats.number",
                FormatRule::Missing {
                    key: key("pattern"),
                },
            ),
        ),
        (
            modules(&[&number("of = number\ndefault = maybe\npattern =\n  {int}")]),
            format(
                "formats.number",
                FormatRule::Text {
                    key: key("default"),
                },
            ),
        ),
        (
            modules(&[&number("of = colour\npattern =\n  {int}")]),
            format(
                "formats.number",
                FormatRule::Unknown {
                    key: key("of"),
                    name: key("colour"),
                },
            ),
        ),
        (
            modules(&[&number("of = number\npattern =\n  {colour}")]),
            format(
                "formats.number",
                FormatRule::Unknown {
                    key: key("pattern"),
                    name: key("colour"),
                },
            ),
        ),
        (
            modules(&[&number("of = number\nselect = plural\npattern =\n  {int}")]),
            format(
                "formats.number",
                FormatRule::Unknown {
                    key: key("select"),
                    name: key("plural"),
                },
            ),
        ),
    ];
    for (loaded, expected) in cases {
        assert_eq!(loaded.expect_err("refused"), expected);
    }
}

#[test]
fn each_call_rule_refuses_its_fixture_when_its_module_loads() {
    let cases = [
        ("hello = {|abc| :number}", call("number", Refusal::Operand)),
        (
            "hello = .local $c = {|abc| :number} {{{$c :integer}}}",
            call("integer", Refusal::Operand),
        ),
        (
            "hello = {|1| :number signDisplay=sometimes}",
            call("number", option("signDisplay")),
        ),
        (
            "hello = {|1| :number colour=red}",
            call("number", option("colour")),
        ),
        (
            "hello = {$n :number select=$s}",
            call("number", option("select")),
        ),
        (
            "hello = {$a :currency currencyDisplay=wide}",
            call("currency", option("currencyDisplay")),
        ),
        (
            "hello = .input {$n :number} .match $n x {{x}} * {{other}}",
            call("number", Refusal::Key { key: key("x") }),
        ),
        (
            "hello = .input {$d :date} .match $d x {{x}} * {{other}}",
            call("date", Refusal::Selector),
        ),
    ];
    for (body, expected) in cases {
        assert_eq!(load(body).expect_err("refused"), expected, "{body}");
    }
}

#[test]
fn each_call_rule_refuses_its_fixture_when_its_message_resolves() {
    let context = modules(&[
        &format!("{TABLES}\n{NUMBER}"),
        "[formats.zone]\nof = time\npattern =\n  [offset?] {offset}",
        "[formats.currency]\nof = amount\noption.currencyDisplay = code name\npattern =\n  {currency} {int}",
        "zone = {$t :zone}\npaid = {$a :currency currencyDisplay=$d}",
    ])
    .expect("the modules load");
    let euros = Amount::new(
        Decimal::parse("5").expect("a decimal"),
        Currency::parse("EUR").expect("a currency"),
    );
    let cases = [
        (
            Given::new("zone").with("t", Time::new(9, 30, None).expect("a time")),
            ResolveError::Operand {
                id: key("zone"),
                function: key("zone"),
            },
        ),
        (
            Given::new("paid")
                .with("a", euros)
                .with("d", String::from("wide")),
            ResolveError::Option {
                id: key("paid"),
                function: key("currency"),
                option: key("currencyDisplay"),
            },
        ),
    ];
    for (given, expected) in cases {
        assert_eq!(context.resolve(&given).expect_err("refused"), expected);
    }
}
