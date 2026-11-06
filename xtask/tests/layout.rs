//! `cargo xtask layout` over small trees: one row per form its rules refuse, and one clean row.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const LIB: &str = "crates/siros-a/src/lib.rs";
const MAIN: &str = "xtask/src/main.rs";
const SHIPPED: &str = "crates/siros-openid4vp/src/lib.rs";

/// A tree beside the base one, and the one hit it gives, at its `file`.
struct Row {
    name: &'static str,
    file: &'static str,
    content: &'static [u8],
    line: usize,
    beside: &'static [(&'static str, &'static str)],
}

const fn row(name: &'static str, file: &'static str, source: &'static str, line: usize) -> Row {
    Row {
        name,
        file,
        content: source.as_bytes(),
        line,
        beside: &[],
    }
}

const ROWS: &[Row] = &[
    // Test attributes, by their path's last segment.
    row("test", LIB, "#[test]\nfn a() {}\n", 1),
    row(
        "test in xtask",
        MAIN,
        "fn main() {}\n#[test]\nfn a() {}\n",
        2,
    ),
    row(
        "test by a path, spaced",
        LIB,
        "# [ tokio :: test ]\nfn a() {}\n",
        1,
    ),
    row(
        "test by a global path",
        LIB,
        "#[::core::prelude::v1::test]\nfn a() {}\n",
        1,
    ),
    row("bench", LIB, "#[bench]\nfn a() {}\n", 1),
    row("rstest", LIB, "#[rstest]\nfn a() {}\n", 1),
    row("test_case", LIB, "#[test_case(1)]\nfn a(n: u8) {}\n", 1),
    row("proptest", LIB, "#[proptest]\nfn a() {}\n", 1),
    row("quickcheck", LIB, "#[quickcheck]\nfn a() {}\n", 1),
    row(
        "wasm_bindgen_test",
        LIB,
        "#[wasm_bindgen_test::wasm_bindgen_test]\nfn a() {}\n",
        1,
    ),
    row("test as a raw identifier", LIB, "#[r#test]\nfn a() {}\n", 1),
    // Every kind of place an attribute goes, at depth.
    row(
        "on a nested item",
        LIB,
        "mod m {\n    mod n {\n        #[test]\n        fn a() {}\n    }\n}\n",
        3,
    ),
    row(
        "in a function",
        LIB,
        "fn f() {\n    #[test]\n    fn a() {}\n}\n",
        2,
    ),
    row(
        "on a field",
        LIB,
        "struct S {\n    #[cfg(test)]\n    a: u8,\n}\n",
        2,
    ),
    row(
        "on a variant",
        LIB,
        "enum E {\n    #[cfg(test)]\n    A,\n}\n",
        2,
    ),
    row(
        "on a statement",
        LIB,
        "fn f() {\n    #[cfg(test)]\n    let a = 1;\n}\n",
        2,
    ),
    row(
        "on an expression",
        LIB,
        "fn f() {\n    #[cfg(test)]\n    {\n        g();\n    }\n}\n",
        2,
    ),
    row(
        "on a match arm",
        LIB,
        "fn f(a: u8) {\n    match a {\n        #[cfg(test)]\n        0 => {}\n        _ => {}\n    }\n}\n",
        3,
    ),
    row("on a parameter", LIB, "fn f(#[cfg(test)] a: u8) {}\n", 1),
    row(
        "on a struct expression's field",
        LIB,
        "fn f() -> S {\n    S {\n        #[cfg(test)]\n        a: 1,\n    }\n}\n",
        3,
    ),
    row(
        "in an impl",
        LIB,
        "impl S {\n    #[cfg(test)]\n    fn a() {}\n}\n",
        2,
    ),
    row(
        "in a trait",
        LIB,
        "trait T {\n    #[cfg(test)]\n    fn a();\n}\n",
        2,
    ),
    row(
        "in a macro's tokens",
        LIB,
        "thread_local! {\n    #[cfg(test)]\n    static A: u8 = 1;\n}\n",
        2,
    ),
    row(
        "in macro_rules",
        LIB,
        "macro_rules! m {\n    () => {\n        #[test]\n        fn a() {}\n    };\n}\n",
        3,
    ),
    // Predicates.
    row("cfg(test)", LIB, "#[cfg(test)]\nmod a {}\n", 1),
    row("inner cfg(test)", LIB, "#![cfg(test)]\n", 1),
    row("cfg(doctest)", LIB, "#[cfg(doctest)]\nmod a {}\n", 1),
    row("cfg(not(test))", LIB, "#[cfg(not(test))]\nmod a {}\n", 1),
    row(
        "cfg in all, any, not",
        LIB,
        "#[cfg(all(feature = \"x\", any(unix, not(doctest))))]\nmod a {}\n",
        1,
    ),
    row(
        "cfg spaced",
        LIB,
        "#[ cfg ( all ( test ) ) ]\nmod a {}\n",
        1,
    ),
    row(
        "cfg_attr(test)",
        LIB,
        "#[cfg_attr(test, derive(Debug))]\nstruct S;\n",
        1,
    ),
    row(
        "inner cfg_attr(not(test))",
        LIB,
        "#![cfg_attr(not(test), deny(clippy::panic))]\n",
        1,
    ),
    row(
        "cfg_attr adding test",
        LIB,
        "#[cfg_attr(feature = \"x\", test)]\nfn a() {}\n",
        1,
    ),
    row(
        "cfg_attr adding cfg(test)",
        LIB,
        "#[cfg_attr(feature = \"x\", cfg(test))]\nfn a() {}\n",
        1,
    ),
    row("cfg(r#test)", LIB, "#[cfg(r#test)]\nmod a {}\n", 1),
    row("r#cfg(test)", LIB, "#[r#cfg(test)]\nmod a {}\n", 1),
    // Macro calls.
    row("proptest!", LIB, "proptest! {\n    fn a() {}\n}\n", 1),
    row("proptest! by a path", LIB, "proptest::proptest! {}\n", 1),
    row(
        "cfg!(test)",
        LIB,
        "fn f() -> bool {\n    cfg!(test)\n}\n",
        2,
    ),
    row(
        "cfg!(not(doctest))",
        LIB,
        "fn f() -> bool {\n    cfg!(not(doctest))\n}\n",
        2,
    ),
    row(
        "cfg! inside a macro",
        LIB,
        "fn f() {\n    g!(cfg!(test));\n}\n",
        2,
    ),
    // Paths and includes.
    row(
        "path out of src",
        LIB,
        "#[path = \"../other/a.rs\"]\nmod a;\n",
        1,
    ),
    row(
        "path to tests",
        LIB,
        "#[path = \"tests/a.rs\"]\nmod a;\n",
        1,
    ),
    row(
        "path from a module out of src",
        "crates/siros-a/src/m/n.rs",
        "#[path = \"../../a.rs\"]\nmod a;\n",
        1,
    ),
    row(
        "cfg_attr adding a path out of src",
        LIB,
        "#[cfg_attr(unix, path = \"../a.rs\")]\nmod a;\n",
        1,
    ),
    row(
        "include! under tests",
        LIB,
        "include!(\"../tests/a.rs\");\n",
        1,
    ),
    row(
        "include_str! under tests",
        LIB,
        "const A: &str = include_str!(\"../tests/a.txt\");\n",
        1,
    ),
    row(
        "include_bytes! under tests",
        LIB,
        "const A: &[u8] = include_bytes!(\"../tests/a.bin\");\n",
        1,
    ),
    row(
        "include_str! of concat! under tests",
        LIB,
        "const A: &str = include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/tests/a.txt\"));\n",
        1,
    ),
    row(
        "include_str! with an escape in the path",
        LIB,
        "const A: &str = include_str!(\"t\\x65sts/a.txt\");\n",
        1,
    ),
    row(
        "path with an escape",
        LIB,
        "#[path = \"t\\x65sts/a.rs\"]\nmod a;\n",
        1,
    ),
    row(
        "doc = include_str! under tests",
        LIB,
        "#[doc = include_str!(\"../tests/a.md\")]\nfn a() {}\n",
        1,
    ),
    row(
        "inner doc = include_str! under tests",
        LIB,
        "#![doc = include_str!(\"../tests/a.md\")]\n",
        1,
    ),
    row(
        "cfg_attr doc = include_str! under tests",
        LIB,
        "#[cfg_attr(unix, doc = include_str!(\"../tests/a.md\"))]\nfn a() {}\n",
        1,
    ),
    row(
        "deprecated note = include_str! under tests",
        LIB,
        "#[deprecated(note = include_str!(\"../tests/a.md\"))]\nfn a() {}\n",
        1,
    ),
    // Message sources.
    row(
        ".mf2 in a crate",
        "crates/siros-a/locales/en.mf2",
        "a = b\n",
        1,
    ),
    row(
        ".mf2 in an engine crate",
        "crates/engine-a/en.mf2",
        "a = b\n",
        1,
    ),
    row(".ftl in a crate", "crates/siros-a/en.ftl", "a = b\n", 1),
    row("upper case", "crates/siros-a/en.MF2", "a = b\n", 1),
    row("mixed case", "crates/siros-a/en.Ftl", "a = b\n", 1),
    row("in xtask", "xtask/en.mf2", "a = b\n", 1),
    row("in xtask's tests", "xtask/tests/en.mf2", "a = b\n", 1),
    row("in a root locales", "locales/en.ftl", "a = b\n", 1),
    row(
        "in a tests directory deeper down",
        "crates/siros-a/sub/tests/en.mf2",
        "a = b\n",
        1,
    ),
    row(
        "include_str! of a message source",
        LIB,
        "const A: &str = include_str!(\"../locales/en.MF2\");\n",
        1,
    ),
    row(
        "include_bytes! of a message source",
        "crates/engine-a/src/lib.rs",
        "const A: &[u8] = include_bytes!(\"en.ftl\");\n",
        1,
    ),
    row("named .mf2 alone", "crates/siros-a/.mf2", "a = b\n", 1),
    row("named .FTL alone", "locales/.FTL", "a = b\n", 1),
    row(
        "include_str! of a file named .mf2 alone",
        LIB,
        "const A: &str = include_str!(\"../.mf2\");\n",
        1,
    ),
    row(
        "doc = include_str! of a message source",
        LIB,
        "#[doc = include_str!(\"../locales/en.mf2\")]\nfn a() {}\n",
        1,
    ),
    row(
        "doc = include_str! of a message source in an engine crate",
        "crates/engine-a/src/lib.rs",
        "#[doc = include_str!(\"en.mf2\")]\nfn a() {}\n",
        1,
    ),
    row(
        "include_str! of a message source from a nested src tree",
        "crates/engine-a/sub/src/lib.rs",
        "const A: &str = include_str!(\"en.mf2\");\n",
        1,
    ),
    row(
        "include_str! of a message source from proving",
        "proving/x/src/lib.rs",
        "const A: &str = include_str!(\"en.mf2\");\n",
        1,
    ),
    // I28.
    row(
        "Text::Raw of a literal",
        SHIPPED,
        "fn f() -> Text {\n    Text::Raw(\"a\".to_owned())\n}\n",
        2,
    ),
    row(
        "Text::Raw by a path",
        SHIPPED,
        "fn f() -> Text {\n    siros_explain::Text::Raw(String::from(\"a\"))\n}\n",
        2,
    ),
    row(
        "Text::Raw of format!",
        SHIPPED,
        "fn f(a: u8) -> Text {\n    Text::Raw(format!(\"{a}\"))\n}\n",
        2,
    ),
    row(
        "Text::Raw inside a macro",
        SHIPPED,
        "fn f() -> Vec<Text> {\n    vec![Text::Raw(\"a\".to_owned())]\n}\n",
        2,
    ),
    row(
        "RequestText::raw of a literal",
        SHIPPED,
        "fn f() -> RequestText {\n    RequestText::raw(\"a\".to_owned())\n}\n",
        2,
    ),
    row(
        "Label::text of a literal",
        SHIPPED,
        "fn f() -> Label {\n    Label::text(\"a\")\n}\n",
        2,
    ),
    row(
        "Label::mini_markdown of a literal",
        SHIPPED,
        "fn f() -> Label {\n    Label::mini_markdown(\"a\")\n}\n",
        2,
    ),
    // I27.
    row(
        "an error without Explain",
        SHIPPED,
        "#[derive(Debug)]\n#[derive(thiserror::Error)]\nenum E {}\n",
        3,
    ),
    row(
        "an error by its import",
        SHIPPED,
        "use thiserror::Error;\n#[derive(Debug, Error)]\nstruct E;\n",
        3,
    ),
    row(
        "an error by a renamed import",
        SHIPPED,
        "use thiserror::{Error as Failure};\n#[derive(Failure)]\nstruct E;\n",
        3,
    ),
    row(
        "an error behind cfg_attr",
        SHIPPED,
        "#[cfg_attr(unix, derive(thiserror::Error))]\nstruct E;\n",
        2,
    ),
    row(
        "an error at depth",
        SHIPPED,
        "fn f() {\n    #[derive(thiserror::Error)]\n    struct E;\n}\n",
        3,
    ),
    row(
        "a text type with Display",
        SHIPPED,
        "#[derive(Explain)]\nenum T {}\nimpl fmt::Display for T {}\n",
        2,
    ),
    row(
        "an error by a grouped import",
        SHIPPED,
        "use {std::fmt, thiserror::Error};\n#[derive(Error)]\nstruct E;\n",
        3,
    ),
    row(
        "an error by a renamed crate",
        SHIPPED,
        "use thiserror as te;\n#[derive(te::Error)]\nstruct E;\n",
        3,
    ),
    row(
        "an error beside a same-named type that implements Explain",
        SHIPPED,
        "mod a {\n    #[derive(thiserror::Error)]\n    struct E;\n}\nmod b {\n    struct E;\n    impl Explain for E {}\n}\n",
        3,
    ),
    Row {
        name: "an error by an import another file re-exports",
        file: "crates/siros-openid4vp/src/a.rs",
        content: b"use crate::Error;\n#[derive(Error)]\nstruct E;\n",
        line: 3,
        beside: &[(SHIPPED, "pub(crate) use thiserror::Error;\n")],
    },
    row(
        "an error in macro_rules",
        SHIPPED,
        "macro_rules! m {\n    () => {\n        #[derive(thiserror::Error)]\n        pub(crate) struct E;\n    };\n}\n",
        4,
    ),
    // What it cannot judge.
    row("does not parse", LIB, "fn a() {}\nfn {\n", 2),
    Row {
        name: "cannot read",
        file: LIB,
        content: b"\xff\xfe",
        line: 1,
        beside: &[],
    },
];

/// `#[cfg(feature = "test-util")]`, as the rows below write it.
macro_rules! gate {
    () => {
        "#[cfg(feature = \"test-util\")]\n"
    };
}

/// One refusal of the test-util rule: its sources, where its one hit stands, the item it names.
struct Refused {
    name: &'static str,
    files: &'static [(&'static str, &'static str)],
    file: &'static str,
    line: usize,
    item: &'static str,
}

const fn refused(
    name: &'static str,
    source: &'static [(&'static str, &'static str)],
    line: usize,
    item: &'static str,
) -> Refused {
    Refused {
        name,
        files: source,
        file: match source {
            [(file, _), ..] => file,
            [] => LIB,
        },
        line,
        item,
    }
}

const REFUSED: &[Refused] = &[
    refused(
        "an inherent impl of a type outside the gate",
        &[(
            LIB,
            concat!(
                "pub struct Token(u8);\n",
                gate!(),
                "impl Token {\n",
                "    pub fn forged() -> Self {\n",
                "        Self(1)\n",
                "    }\n",
                "}\n",
            ),
        )],
        3,
        "impl Token",
    ),
    refused(
        "a gated associated function",
        &[(
            LIB,
            concat!(
                "pub struct Token(u8);\n",
                "impl Token {\n",
                "    #[cfg(feature = \"test-util\")]\n",
                "    pub fn forged() -> Self {\n",
                "        Self(1)\n",
                "    }\n",
                "}\n",
            ),
        )],
        3,
        "Token::forged",
    ),
    refused(
        "a trait impl on a type with private fields",
        &[(
            LIB,
            concat!(
                "pub struct Token(u8);\n",
                gate!(),
                "impl Default for Token {\n",
                "    fn default() -> Self {\n",
                "        Self(1)\n",
                "    }\n",
                "}\n",
            ),
        )],
        3,
        "impl Default for Token",
    ),
    refused(
        "a pub function that gives a type with private fields",
        &[(
            LIB,
            concat!(
                "pub struct Token(u8);\n",
                "impl Token {\n",
                "    pub fn new() -> Self {\n",
                "        Self(0)\n",
                "    }\n",
                "}\n",
                gate!(),
                "pub fn forged() -> Option<Token> {\n",
                "    Some(Token::new())\n",
                "}\n",
            ),
        )],
        8,
        "forged",
    ),
    refused(
        "a pub const of a type with private fields",
        &[(
            LIB,
            concat!(
                "pub struct Token(u8);\n",
                gate!(),
                "pub const FORGED: Token = Token(1);\n",
            ),
        )],
        3,
        "FORGED",
    ),
    refused(
        "a literal of a type with private fields",
        &[(
            LIB,
            concat!(
                "pub struct Token {\n",
                "    a: u8,\n",
                "}\n",
                gate!(),
                "fn forged() -> u8 {\n",
                "    Token { a: 1 }.a\n",
                "}\n",
            ),
        )],
        6,
        "forged",
    ),
    refused(
        "a tuple constructor of a type with private fields",
        &[(
            LIB,
            concat!(
                "pub struct Token(u8);\n",
                gate!(),
                "fn forged() -> u8 {\n",
                "    Token(1).0\n",
                "}\n",
            ),
        )],
        4,
        "forged",
    ),
    refused(
        "a literal in a macro's arguments",
        &[(
            LIB,
            concat!(
                "pub struct Token(u8);\n",
                gate!(),
                "fn forged() -> Vec<Token> {\n",
                "    vec![Token(1)]\n",
                "}\n",
            ),
        )],
        4,
        "forged",
    ),
    refused(
        "a call of a crate-private constructor",
        &[(
            LIB,
            concat!(
                "pub struct Token(u8);\n",
                "impl Token {\n",
                "    pub(crate) fn raw() -> Self {\n",
                "        Self(1)\n",
                "    }\n",
                "}\n",
                gate!(),
                "fn forged() -> u8 {\n",
                "    Token::raw().0\n",
                "}\n",
            ),
        )],
        9,
        "forged",
    ),
    refused(
        "a call of a crate-private method that makes the value",
        &[(
            LIB,
            concat!(
                "pub struct Token(u8);\n",
                "impl Token {\n",
                "    pub(crate) fn twin(&self) -> Self {\n",
                "        Self(self.0)\n",
                "    }\n",
                "}\n",
                gate!(),
                "fn forged(token: &Token) -> u8 {\n",
                "    token.twin().0\n",
                "}\n",
            ),
        )],
        9,
        "forged",
    ),
    refused(
        "a value in a file a gated mod loads",
        &[
            (
                "crates/siros-a/src/util.rs",
                "use crate::Token;\nfn forged() -> u8 {\n    Token(1).0\n}\n",
            ),
            (
                LIB,
                concat!("pub struct Token(u8);\n", gate!(), "mod util;\n"),
            ),
        ],
        3,
        "forged",
    ),
    refused(
        "a value in a file its inner attribute gates",
        &[
            (
                "crates/siros-a/src/util.rs",
                concat!(
                    "#![cfg(feature = \"test-util\")]\n",
                    "use crate::Token;\n",
                    "fn forged() -> u8 {\n",
                    "    Token(1).0\n",
                    "}\n",
                ),
            ),
            (LIB, "pub struct Token(u8);\nmod util;\n"),
        ],
        4,
        "forged",
    ),
    refused(
        "a gate inside a predicate",
        &[(
            LIB,
            concat!(
                "pub struct Token(u8);\n",
                "#[cfg(all(feature = \"x\", any(feature = \"test-util\", feature = \"y\")))]\n",
                "impl Token {}\n",
            ),
        )],
        3,
        "impl Token",
    ),
    refused(
        "a re-export of an item outside the gate",
        &[(
            LIB,
            concat!(
                "mod a {\n",
                "    pub fn forged() -> u8 {\n",
                "        1\n",
                "    }\n",
                "}\n",
                gate!(),
                "pub use a::forged;\n",
            ),
        )],
        7,
        "use a::forged",
    ),
    refused(
        "a glob re-export",
        &[(LIB, concat!("mod a {}\n", gate!(), "pub use a::*;\n"))],
        3,
        "use a::*",
    ),
    refused(
        "a macro in item position",
        &[(LIB, concat!(gate!(), "forge!(Token);\n"))],
        2,
        "forge!",
    ),
    refused(
        "a gate in a macro's tokens",
        &[(
            LIB,
            concat!(
                "macro_rules! m {\n",
                "    () => {\n",
                "        #[cfg(feature = \"test-util\")]\n",
                "        impl Token {}\n",
                "    };\n",
                "}\n",
            ),
        )],
        1,
        "m!",
    ),
    refused(
        "a gate on a field",
        &[(
            LIB,
            "pub struct Token {\n    #[cfg(feature = \"test-util\")]\n    pub a: u8,\n}\n",
        )],
        2,
        "Token",
    ),
    refused(
        "a cfg_attr gate",
        &[(
            LIB,
            "#[cfg_attr(feature = \"test-util\", derive(Default))]\npub struct Token(u8);\n",
        )],
        1,
        "Token",
    ),
    refused(
        "a path attribute on a gated module",
        &[(LIB, concat!(gate!(), "#[path = \"u.rs\"]\nmod util;\n"))],
        3,
        "util",
    ),
];

/// The forms next to the rules' forms that the rules leave alone.
const CLEAN: &[(&str, &str)] = &[
    (
        LIB,
        concat!(
            "// #[test]\n",
            "//! #[cfg(test)]\n",
            "/// `#[test]`, `cfg!(test)`.\n",
            "#[cfg(feature = \"test-util\")]\n",
            "mod util;\n",
            "#[cfg(feature = \"test\")]\n",
            "mod named;\n",
            "#[cfg_attr(feature = \"x\", derive(Debug))]\n",
            "struct S;\n",
            "#[path = \"m/n.rs\"]\n",
            "mod o;\n",
            "mod inline {\n",
            "    #[path = \"../a.rs\"]\n",
            "    mod a;\n",
            "}\n",
            "fn f(test: u8) -> &'static str {\n",
            "    let tests = \"#[test] cfg!(test) tests/a.mf2\";\n",
            "    g!(test, not_a_cfg!(test));\n",
            "    include_str!(\"data/a.txt\")\n",
            "}\n",
        ),
    ),
    ("crates/siros-a/tests/en.mf2", "a = b\n"),
    ("proving/en.mf2", "a = b\n"),
    (
        "proving/target/debug/src/a.rs",
        "const A: &str = include_str!(\"en.mf2\");\n",
    ),
    (
        "proving/x/tests/a.rs",
        "const A: &str = include_str!(\"en.mf2\");\n",
    ),
    ("crates/siros-a/tests/deep/en.ftl", "a = b\n"),
    ("crates/siros-a/tests/a.rs", "#[test]\nfn a() {}\n"),
    ("crates/siros-testkit/locales/en.mf2", "a = b\n"),
    (
        "crates/siros-testkit/src/lib.rs",
        "const A: &str = include_str!(\"../locales/en.mf2\");\nfn f() -> Text {\n    Text::Raw(\"a\".to_owned())\n}\n",
    ),
    (
        "crates/engine-a/src/lib.rs",
        "#[cfg(test)]\nmod a {\n    #[test]\n    fn b() {}\n}\n",
    ),
    (
        SHIPPED,
        concat!(
            "fn f(a: &str, n: Text) -> bool {\n",
            "    let _ = Text::Raw(a.to_owned());\n",
            "    let _ = Label::text(a);\n",
            "    let _ = Other::text(\"a\");\n",
            "    matches!(n, Text::Raw(_))\n",
            "}\n",
            "#[derive(Debug, thiserror::Error, siros_explain::Explain)]\n",
            "enum Derived {}\n",
            "#[derive(thiserror::Error)]\n",
            "struct ByHand;\n",
            "impl siros_explain::Explain for ByHand {}\n",
            "#[derive(Explain)]\n",
            "enum Worded {}\n",
            "#[derive(Explain)]\n",
            "struct HandError;\n",
            "impl fmt::Display for HandError {}\n",
            "impl std::error::Error for HandError {}\n",
            "mod glob {\n",
            "    use super::*;\n",
            "    #[derive(thiserror::Error)]\n",
            "    struct ThroughGlob;\n",
            "    impl Explain for self::ThroughGlob {}\n",
            "}\n",
            "macro_rules! typed {\n",
            "    ($name:ident) => {\n",
            "        #[derive(thiserror::Error)]\n",
            "        struct $name;\n",
            "        impl Explain for $name {}\n",
            "    };\n",
            "}\n",
        ),
    ),
    (
        "crates/siros-x509/src/a.rs",
        "#[derive(thiserror::Error)]\nstruct InAnotherFile;\n",
    ),
    (
        "crates/siros-x509/src/b.rs",
        "use crate::a::InAnotherFile;\nimpl Explain for InAnotherFile {}\n",
    ),
    (
        "crates/siros-testkit/src/c.rs",
        "#[derive(thiserror::Error)]\nstruct Unshipped;\n",
    ),
    (
        "crates/siros-double/src/lib.rs",
        concat!(
            "pub trait Ids {\n",
            "    fn id(&self) -> Id;\n",
            "}\n",
            "pub struct Id(u64);\n",
            "impl Id {\n",
            "    pub const fn new(value: u64) -> Self {\n",
            "        Self(value)\n",
            "    }\n",
            "}\n",
            "pub struct Reading {\n",
            "    pub value: u64,\n",
            "}\n",
            gate!(),
            "mod test_util {\n",
            "    use super::{Id, Ids, Reading};\n",
            "    fn next(issued: u64) -> u64 {\n",
            "        issued + 1\n",
            "    }\n",
            "    #[derive(Default)]\n",
            "    pub struct TestIds {\n",
            "        issued: u64,\n",
            "    }\n",
            "    impl TestIds {\n",
            "        pub fn after(issued: u64) -> Self {\n",
            "            Self { issued }\n",
            "        }\n",
            "        pub fn reading(&self) -> Reading {\n",
            "            Reading { value: self.issued }\n",
            "        }\n",
            "    }\n",
            "    impl Ids for TestIds {\n",
            "        fn id(&self) -> Id {\n",
            "            Id::new(next(self.issued))\n",
            "        }\n",
            "    }\n",
            "}\n",
            gate!(),
            "pub use test_util::TestIds;\n",
        ),
    ),
];

/// Writes the base tree, whose files every row overwrites or adds to, under a fresh directory.
fn tree(name: &str, files: &[(&str, &[u8])]) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("layout")
        .join(
            name.chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect::<String>(),
        );
    if root.exists() {
        fs::remove_dir_all(&root).expect("the old tree");
    }
    let base: [(&str, &[u8]); 2] = [(LIB, b"fn a() {}\n"), (MAIN, b"fn main() {}\n")];
    for (file, content) in base.iter().chain(files) {
        let path = root.join(file);
        fs::create_dir_all(path.parent().expect("a directory")).expect("the directory");
        fs::write(path, content).expect("the file");
    }
    root
}

/// The exit status and each hit's line of output.
fn layout_lines(root: &Path) -> (Option<i32>, Vec<String>) {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["layout".as_ref(), root.as_os_str()])
        .output()
        .expect("xtask runs");
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    let hits = stdout
        .lines()
        .filter(|line| !line.starts_with("layout hits: "))
        .map(str::to_owned)
        .collect();
    (output.status.code(), hits)
}

/// The exit status and each hit's `file:line`.
fn layout(root: &Path) -> (Option<i32>, Vec<String>) {
    let (code, lines) = layout_lines(root);
    let hits = lines
        .iter()
        .map(|line| line.splitn(3, ':').take(2).collect::<Vec<_>>().join(":"))
        .collect();
    (code, hits)
}

#[test]
fn each_form_is_a_hit_at_its_file_and_line() {
    let mut wrong = Vec::new();
    for row in ROWS {
        let beside = row
            .beside
            .iter()
            .map(|(file, source)| (*file, source.as_bytes()));
        let files: Vec<(&str, &[u8])> = std::iter::once((row.file, row.content))
            .chain(beside)
            .collect();
        let root = tree(row.name, &files);
        let got = layout(&root);
        let want = (Some(1), vec![format!("{}:{}", row.file, row.line)]);
        if got != want {
            wrong.push(format!("{}: {got:?}, expected {want:?}", row.name));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A parse error or an unread file gives another rule at the same place: each row's hit names the
/// test-util rule and the item.
#[test]
fn each_test_util_refusal_names_its_item_at_its_place() {
    let mut wrong = Vec::new();
    for row in REFUSED {
        let files: Vec<(&str, &[u8])> = row
            .files
            .iter()
            .map(|(file, source)| (*file, source.as_bytes()))
            .collect();
        let (code, lines) = layout_lines(&tree(row.name, &files));
        let want = format!("{}:{}: test-util: `{}`: ", row.file, row.line, row.item);
        if code != Some(1) || lines.len() != 1 || !lines.iter().all(|l| l.starts_with(&want)) {
            wrong.push(format!("{}: {code:?} {lines:?}, expected {want}", row.name));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_clean_tree_exits_zero_with_no_hit() {
    let files: Vec<(&str, &[u8])> = CLEAN
        .iter()
        .map(|(file, source)| (*file, source.as_bytes()))
        .collect();
    assert_eq!(layout(&tree("clean", &files)), (Some(0), Vec::new()));
}
