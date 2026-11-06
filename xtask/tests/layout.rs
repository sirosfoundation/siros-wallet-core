//! `cargo xtask layout` over small trees: one row per form its rules refuse, and one clean row.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const LIB: &str = "crates/siros-a/src/lib.rs";
const MAIN: &str = "xtask/src/main.rs";
const SHIPPED: &str = "crates/siros-openid4vp/src/lib.rs";

/// A tree beside the base one, and the one hit it gives.
struct Row {
    name: &'static str,
    file: &'static str,
    content: &'static [u8],
    line: usize,
}

const fn row(name: &'static str, file: &'static str, source: &'static str, line: usize) -> Row {
    Row {
        name,
        file,
        content: source.as_bytes(),
        line,
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
    // What it cannot judge.
    row("does not parse", LIB, "fn a() {}\nfn {\n", 2),
    Row {
        name: "cannot read",
        file: LIB,
        content: b"\xff\xfe",
        line: 1,
    },
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
        ),
    ),
    (
        "crates/siros-openid4vp/src/test_util.rs",
        "fn f() -> Text {\n    Text::Raw(\"a\".to_owned())\n}\n",
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

/// The exit status and each hit's `file:line`.
fn layout(root: &Path) -> (Option<i32>, Vec<String>) {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["layout".as_ref(), root.as_os_str()])
        .output()
        .expect("xtask runs");
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    let hits = stdout
        .lines()
        .filter(|line| !line.starts_with("layout hits: "))
        .map(|line| line.splitn(3, ':').take(2).collect::<Vec<_>>().join(":"))
        .collect();
    (output.status.code(), hits)
}

#[test]
fn each_form_is_a_hit_at_its_file_and_line() {
    let mut wrong = Vec::new();
    for row in ROWS {
        let root = tree(row.name, &[(row.file, row.content)]);
        let got = layout(&root);
        let want = (Some(1), vec![format!("{}:{}", row.file, row.line)]);
        if got != want {
            wrong.push(format!("{}: {got:?}, expected {want:?}", row.name));
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
