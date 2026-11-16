//! An argument takes the formats of its type's name: a placeholder, a declaration or a selector
//! without a function takes the default format, a type the formatter does not register takes
//! `:string`, a call of a format of another name refuses, and a call on another call's value
//! formats the root value by the outer function with that function's options along the chain.

use std::fmt;

use siros_i18n::{Bidi, Context, Refusal, ResolveError};
use siros_syntax::Date;

use crate::{Given, cldr};

/// A name, of a type the formatter does not register.
struct Name(&'static str);

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

const BODY: &str = "\
bare = {$n}
input = .input {$n} {{{$n}}}
named = {$n :integer useGrouping=never}
string = {$n :string}
name = {$who}
plural = .match $n one {{one}} * {{other}}
same = .local $i = {$n :number useGrouping=never} {{{$i :number minimumFractionDigits=1}}}
other = .local $i = {$n :number useGrouping=never} {{{$i :integer}}}
untaken = {$n :currency}
untaken_name = {$who :number}
day = .match $d |2026-11-13| {{that day}} * {{another}}
key = .match $n |x| {{x}} * {{other}}";

fn context() -> Context {
    cldr::context("en", Bidi::None, BODY).expect("the modules load")
}

fn resolve(context: &Context, id: &'static str, n: u32) -> Result<String, ResolveError> {
    let given = Given::new(id)
        .with("n", n)
        .with("who", Name("Ada"))
        .with("d", Date::new(2026, 11, 13).expect("a date"));
    context.resolve(&given).map(|text| text.to_string())
}

#[test]
fn an_argument_takes_its_types_formats() {
    let context = context();
    let resolved = [
        ("bare", 1234, Ok("1,234")),
        ("input", 1234, Ok("1,234")),
        ("named", 1234, Ok("1234")),
        ("string", 1234, Ok("1234")),
        ("name", 1, Ok("Ada")),
        ("plural", 1, Ok("one")),
        ("plural", 2, Ok("other")),
        ("same", 1234, Ok("1234.0")),
        ("other", 1234, Ok("1,234")),
    ];
    for (id, n, text) in resolved {
        assert_eq!(resolve(&context, id, n).as_deref(), text, "{id} over {n}");
    }
    let refused = [
        (
            "untaken",
            ResolveError::Unformatted {
                id: "untaken".to_owned(),
                key: "n".to_owned(),
                function: "currency".to_owned(),
            },
        ),
        (
            "untaken_name",
            ResolveError::Unformatted {
                id: "untaken_name".to_owned(),
                key: "who".to_owned(),
                function: "number".to_owned(),
            },
        ),
        (
            "day",
            ResolveError::Selector {
                id: "day".to_owned(),
                function: "date".to_owned(),
                refusal: Refusal::Selector,
            },
        ),
        (
            "key",
            ResolveError::Selector {
                id: "key".to_owned(),
                function: "number".to_owned(),
                refusal: Refusal::Key {
                    key: "x".to_owned(),
                },
            },
        ),
    ];
    for (id, error) in refused {
        assert_eq!(resolve(&context, id, 1), Err(error), "{id}");
    }
}
