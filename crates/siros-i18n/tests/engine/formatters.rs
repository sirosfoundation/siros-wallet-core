//! An argument takes the formatters its type registers: a placeholder, a declaration or a
//! selector without a function takes the type's default, a type without one takes `:string`,
//! and a call of a function the type does not take refuses. Each registration rule refuses its
//! fixture.

use std::any::type_name;
use std::fmt;

use siros_i18n::{Arg, Bidi, Context, Formatters, Message, Refusal, RegisterError, ResolveError};

use crate::{cldr, english};

/// A count, its `Display` the number literal; `:number` by default, `:integer` by name.
struct Count(u32);

/// A name, which registers no formatter.
struct Name(&'static str);

/// A day, its `Display` the ISO 8601 date; `:siros:date` by default, which does not select.
struct Day(&'static str);

impl fmt::Display for Count {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl fmt::Display for Day {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// The message `id` over a count `n`, a name `who` and a day `d`.
struct Typed {
    id: &'static str,
    n: Count,
    who: Name,
    d: Day,
}

impl Message for Typed {
    fn id(&self) -> &str {
        self.id
    }

    fn arg(&self, key: &str) -> Option<&dyn Arg> {
        match key {
            "n" => Some(&self.n),
            "who" => Some(&self.who),
            "d" => Some(&self.d),
            _ => None,
        }
    }
}

const BODY: &str = "\
bare = {$n}
input = .input {$n} {{{$n}}}
named = {$n :integer useGrouping=never}
string = {$n :string}
name = {$who}
plural = .match $n one {{one}} * {{other}}
untaken = {$n :percent}
untaken_name = {$who :number}
day = .match $d |2026-11-13| {{that day}} * {{another}}
key = .match $n |x| {{x}} * {{other}}";

fn context() -> Context {
    let formats = cldr::formats("en").expect("the en fixture");
    let formatters = Formatters::new()
        .default_formatter::<Count>("number")
        .and_then(|formatters| formatters.formatter::<Count>("integer"))
        .and_then(|formatters| formatters.default_formatter::<Day>("siros:date"))
        .expect("the build has the functions");
    Context::new()
        .bidi(Bidi::None)
        .formatters(formatters)
        .module(&formats)
        .and_then(|context| context.module(&english(BODY)))
        .expect("the modules load")
}

fn resolve(context: &Context, id: &'static str, n: u32) -> Result<String, ResolveError> {
    let typed = Typed {
        id,
        n: Count(n),
        who: Name("Ada"),
        d: Day("2026-11-13"),
    };
    context.resolve(&typed).map(|text| text.to_string())
}

#[test]
fn an_argument_takes_its_types_formatters() {
    let context = context();
    let resolved = [
        ("bare", 1234, Ok("1,234")),
        ("input", 1234, Ok("1,234")),
        ("named", 1234, Ok("1234")),
        ("string", 1234, Ok("1234")),
        ("name", 1, Ok("Ada")),
        ("plural", 1, Ok("one")),
        ("plural", 2, Ok("other")),
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
                function: "percent".to_owned(),
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
                function: "siros:date".to_owned(),
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

#[test]
fn each_registration_rule_refuses_its_fixture() {
    let count = type_name::<Count>();
    let cases = [
        (
            Formatters::new().formatter::<Count>("nothing"),
            RegisterError::Function {
                name: "nothing".to_owned(),
            },
        ),
        (
            Formatters::new()
                .formatter::<Count>("integer")
                .and_then(|formatters| formatters.default_formatter::<Count>("integer")),
            RegisterError::Repeated {
                of: count,
                name: "integer".to_owned(),
            },
        ),
        (
            Formatters::new()
                .default_formatter::<Count>("number")
                .and_then(|formatters| formatters.default_formatter::<Count>("integer")),
            RegisterError::Default { of: count },
        ),
    ];
    for (registered, error) in cases {
        assert_eq!(registered.err(), Some(error));
    }
}
