//! One fixture per refusal, each refused for its rule and no other. MF2's data-model rules and
//! its error types are the conformance suite's.

use std::fmt::{self, Display};

use siros_i18n::{
    Bidi, Context, FormatRule, LoadError, LocaleTag, Message, Refusal, ResolveError, SyntaxRule,
};

use crate::{Given, cldr, english};

/// The CLDR tool's English formats with `from` replaced by `to` once.
fn formats(from: &str, to: &str) -> String {
    let formats = cldr::formats("en").expect("the en fixture");
    assert!(formats.contains(from), "the fixture holds {from:?}");
    formats.replacen(from, to, 1)
}

/// A context of the English formats and a module of `body`.
fn load(body: &str) -> Result<Context, LoadError> {
    cldr::context("en", Bidi::None, body)
}

fn syntax(line: usize, rule: SyntaxRule) -> LoadError {
    LoadError::Syntax { line, rule }
}

fn tag(text: &str) -> LocaleTag {
    LocaleTag::parse(text).expect("a tag")
}

#[test]
fn each_load_rule_refuses_its_fixture() {
    let hello = || "hello".to_owned();
    let cases: Vec<(Result<Context, LoadError>, LoadError)> = vec![
        (
            Context::new().module("@locale en\n---\n  stray\n"),
            syntax(3, SyntaxRule::Line),
        ),
        (
            Context::new().module("@locale en\n---\nhello = a\n  b\u{7}c\n"),
            syntax(4, SyntaxRule::Line),
        ),
        (
            Context::new().module("@locale en\n---\nhello = Hel\\qlo\n"),
            syntax(3, SyntaxRule::Escape),
        ),
        (
            Context::new().module("@locale en\n"),
            syntax(2, SyntaxRule::Frontmatter),
        ),
        (
            Context::new().module("@locale en\n---\n---\n"),
            syntax(3, SyntaxRule::Frontmatter),
        ),
        (
            Context::new().module("hello = x\n@locale en\n---\n"),
            syntax(1, SyntaxRule::Order),
        ),
        (
            Context::new().module("@author someone\n@locale en\n---\n"),
            syntax(
                1,
                SyntaxRule::Metadata {
                    name: "author".to_owned(),
                },
            ),
        ),
        (
            Context::new().module("@locale e_n\n---\n"),
            syntax(
                1,
                SyntaxRule::Tag {
                    tag: "e_n".to_owned(),
                },
            ),
        ),
        (
            Context::new().module("@locale en\n@dir up\n---\n"),
            syntax(
                2,
                SyntaxRule::Direction {
                    direction: "up".to_owned(),
                },
            ),
        ),
        (
            load("hello = {Hello"),
            syntax(4, SyntaxRule::Message { id: hello(), at: 6 }),
        ),
        (
            load("hello = {#bold}Hello{/bold}"),
            syntax(
                4,
                SyntaxRule::Markup {
                    id: hello(),
                    markup: "bold".to_owned(),
                },
            ),
        ),
        (
            load("hello = {#strong a=b}Hello{/strong}"),
            syntax(
                4,
                SyntaxRule::MarkupOption {
                    id: hello(),
                    markup: "strong".to_owned(),
                },
            ),
        ),
        (
            load("hello = {#strong}Hello"),
            syntax(
                4,
                SyntaxRule::Nesting {
                    id: hello(),
                    markup: "strong".to_owned(),
                },
            ),
        ),
        (
            load("hello = a\nhello = b"),
            LoadError::Repeated { id: hello() },
        ),
        (
            load("hello = a").and_then(|context| context.module(&english("hello = b"))),
            LoadError::Repeated { id: hello() },
        ),
        (
            load("hello = a").and_then(|context| context.module(&cldr::formats("en").expect("en"))),
            LoadError::Repeated {
                id: "formats.number".to_owned(),
            },
        ),
        (
            Context::new().module(&formats(
                "[formats.number]\n",
                "[formats.number]\nzero = 0\n",
            )),
            LoadError::Repeated {
                id: "formats.number.zero".to_owned(),
            },
        ),
        (
            Context::new().module("---\nhello = a\n"),
            LoadError::Locale {
                locale: None,
                context: None,
            },
        ),
        (
            load("hello = a").and_then(|context| context.module("@locale de\n---\nbye = b\n")),
            LoadError::Locale {
                locale: Some(tag("de")),
                context: Some(tag("en")),
            },
        ),
        (
            load("hello = {|x| :nothing}"),
            LoadError::Function {
                id: hello(),
                function: "nothing".to_owned(),
            },
        ),
        (
            Context::new().module(&english("hello = {$n :number}")),
            LoadError::Option {
                id: hello(),
                function: "number".to_owned(),
            },
        ),
        (
            Context::new().module(&formats(
                "[formats.number]\n",
                "[formats.colour]\nx = y\n\n[formats.number]\n",
            )),
            LoadError::Format {
                format: "colour".to_owned(),
                rule: FormatRule::Unknown,
            },
        ),
        (
            Context::new().module(&formats(
                "[formats.number]\n",
                "[formats.number]\ncolour = red\n",
            )),
            LoadError::Format {
                format: "number".to_owned(),
                rule: FormatRule::Undefined {
                    option: "colour".to_owned(),
                },
            },
        ),
        (
            Context::new().module(&formats("zero = 0\n", "")),
            LoadError::Format {
                format: "number".to_owned(),
                rule: FormatRule::Missing { option: "zero" },
            },
        ),
        (
            Context::new().module(&formats("grouping = 1", "grouping = 0")),
            LoadError::Format {
                format: "number".to_owned(),
                rule: FormatRule::Text { option: "grouping" },
            },
        ),
        (
            load("hello = {|abc| :number}"),
            LoadError::Call {
                id: hello(),
                function: "number".to_owned(),
                refusal: Refusal::Operand,
            },
        ),
        (
            load("hello = .local $c = {|abc| :number} {{{$a :currency currency=$c}}}"),
            LoadError::Call {
                id: hello(),
                function: "number".to_owned(),
                refusal: Refusal::Operand,
            },
        ),
    ];
    for (loaded, expected) in cases {
        assert_eq!(loaded.expect_err("refused"), expected);
    }
}

/// A value whose `Display` fails.
struct Undisplayable;

impl Display for Undisplayable {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Err(fmt::Error)
    }
}

/// A message that gives its key `n` twice, or once by a value that fails to display.
enum Broken {
    Twice,
    Undisplayable,
}

impl Message for Broken {
    fn id(&self) -> &str {
        "count"
    }

    fn args(&self, arg: &mut dyn FnMut(&str, &dyn Display)) {
        match self {
            Self::Twice => {
                arg("n", &"1");
                arg("n", &"2");
            }
            Self::Undisplayable => arg("n", &Undisplayable),
        }
    }
}

#[test]
fn each_resolution_rule_refuses_its_fixture() {
    let context = load(
        "hello = Hello {$name}\n\
         count = {$n :number}\n\
         paid = {$amount :currency currency=$code}\n\
         dir = {$name :string u:dir=$dir}\n\
         digits = .input {$n :integer} {{{|1| :number minimumFractionDigits=$n}}}",
    )
    .expect("the module loads");
    let id = |id: &str| id.to_owned();
    let paid = Given {
        id: "paid",
        args: vec![("amount", "5".to_owned()), ("code", "euro".to_owned())],
    };
    let dir = Given {
        id: "dir",
        args: vec![("name", "Ann".to_owned()), ("dir", "up".to_owned())],
    };
    let cases: [(&dyn Message, ResolveError); 8] = [
        (&Given::bare("bye"), ResolveError::Unknown { id: id("bye") }),
        (
            &Given::bare("hello"),
            ResolveError::Unresolved {
                id: id("hello"),
                key: "name".to_owned(),
            },
        ),
        (
            &Given::with("count", "n", "five"),
            ResolveError::Operand {
                id: id("count"),
                function: "number".to_owned(),
            },
        ),
        (
            &paid,
            ResolveError::Option {
                id: id("paid"),
                function: "currency".to_owned(),
                option: "currency".to_owned(),
            },
        ),
        (
            &dir,
            ResolveError::Option {
                id: id("dir"),
                function: "string".to_owned(),
                option: "u:dir".to_owned(),
            },
        ),
        (
            &Given::with("digits", "n", "two"),
            ResolveError::Option {
                id: id("digits"),
                function: "number".to_owned(),
                option: "minimumFractionDigits".to_owned(),
            },
        ),
        (
            &Broken::Twice,
            ResolveError::Argument {
                id: id("count"),
                key: "n".to_owned(),
            },
        ),
        (
            &Broken::Undisplayable,
            ResolveError::Argument {
                id: id("count"),
                key: "n".to_owned(),
            },
        ),
    ];
    for (message, expected) in cases {
        assert_eq!(context.resolve(message).expect_err("refused"), expected);
    }
}

/// `Context::module_in_nfc` refuses a name, a variant key and a selector literal that NFC
/// changes, each naming it as written, and loads text and a literal a placeholder formats as
/// written. U+1E0A U+0323 is outside NFC, which writes it U+1E0C U+0307 (UAX #15; the
/// conformance suite's "NFC:" cases).
#[cfg(feature = "nfc")]
#[test]
fn module_in_nfc_refuses_each_item_nfc_changes() {
    const WRITTEN: &str = "\u{1E0A}\u{323}";
    const NORMAL: &str = "\u{1E0C}\u{307}";
    let unnormalized = LoadError::Unnormalized {
        id: "hello".to_owned(),
        text: WRITTEN.to_owned(),
    };
    // A variable's name, a variant key, and the literal a `:string` selector compares.
    let refused = [
        format!("{{${WRITTEN}}}"),
        format!(".input {{$x :string}} .match $x {WRITTEN} {{{{a}}}} * {{{{b}}}}"),
        format!(".local $x = {{|{WRITTEN}| :string}} .match $x {NORMAL} {{{{a}}}} * {{{{b}}}}"),
    ];
    for message in refused {
        assert_eq!(
            Context::new()
                .module_in_nfc(&english(&format!("hello = {message}")))
                .expect_err("refused"),
            unnormalized,
            "{message:?}"
        );
    }
    let context = Context::new()
        .bidi(Bidi::None)
        .module_in_nfc(&english(&format!(
            "hello = .local $y = {{|{WRITTEN}| :string}} {{{{{WRITTEN} {{$y}} {{|{WRITTEN}|}} {{$name}}}}}}"
        )))
        .expect("loads");
    let text = context
        .resolve(&Given::with("hello", "name", WRITTEN))
        .expect("resolves");
    assert_eq!(text.to_string(), [WRITTEN; 4].join(" "));
}
