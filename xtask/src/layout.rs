//! `cargo xtask layout [<root>]`: the layout AGENTS.md's rules give, over the syntax trees.
//! Each hit prints as `file:line: rule`, a file it cannot read or parse included.
//!
//! - Test code under `crates/siros-*/src` and `xtask/src`: a test attribute, a `cfg` or `cfg_attr`
//!   naming `test` or `doctest`, `proptest!`, `cfg!` over such a predicate, a `#[path]` that leaves
//!   `src/` or enters a `tests` directory, an `include!` family call of a path under `tests`.
//! - Message sources: `.mf2` and `.ftl` files under `crates`, `xtask` and `locales`, outside
//!   `crates/<crate>/tests/` and `crates/siros-testkit/`, and an `include_str!` or
//!   `include_bytes!` of one from a `src/` tree under `crates`, `xtask` or `proving`, outside
//!   `crates/siros-testkit/`.
//! - I28, in the shipped crates' sources: a `Text::Raw` or `RequestText::raw` built from a literal
//!   or a `format!`, a `Label::text` or `Label::mini_markdown` of a literal.
//! - I27, in the same sources: a type deriving `thiserror::Error` that neither derives nor
//!   implements `Explain`; a type deriving `Explain` alone that implements `Display`.
//! - `feature = "test-util"`, in every source: see [`gate`].
//!
//! Macro bodies and attribute values are token trees to `syn`: the same rules read their tokens.

mod gate;
mod names;

use std::fs;
use std::path::Path;

use proc_macro2::{Delimiter, Group, Ident, Literal, TokenStream, TokenTree};
use quote::ToTokens;
use syn::ext::IdentExt;
use syn::visit::{self, Visit};

use self::gate::Gates;
use self::names::{Names, module_of};
use crate::Failure;

/// The presentation core's crates whose texts reach the End-User (design section 4.11).
const SHIPPED: [&str; 10] = [
    "siros-openid4vp",
    "siros-x509",
    "siros-mdoc",
    "siros-sdjwt",
    "siros-paso",
    "siros-qes",
    "siros-credman",
    "siros-webuild",
    "siros-i18n",
    "siros-explain",
];

/// Attributes that mark a test, by their path's last segment.
const TEST_ATTRIBUTES: [&str; 7] = [
    "test",
    "bench",
    "rstest",
    "test_case",
    "proptest",
    "quickcheck",
    "wasm_bindgen_test",
];

/// The calls that build a display text, as a type and a function.
const DISPLAY_CALLS: [(&str, &str); 4] = [
    ("Text", "Raw"),
    ("RequestText", "raw"),
    ("Label", "text"),
    ("Label", "mini_markdown"),
];

/// A place the layout's rules refuse.
struct Hit {
    file: String,
    line: usize,
    rule: String,
}

/// Which rules a source file answers to.
#[derive(Clone, Copy)]
struct Scope {
    test_code: bool,
    message_includes: bool,
    shipped: bool,
}

impl Scope {
    /// The scope of a `.rs` file by its path from the root; `None` when no rule reads it.
    fn of(file: &str) -> Option<Self> {
        let parts: Vec<&str> = file.split('/').collect();
        let scope = match parts.as_slice() {
            ["xtask", "src", ..] => Self {
                test_code: true,
                message_includes: true,
                shipped: false,
            },
            ["crates", name, "src", ..] => Self {
                test_code: name.starts_with("siros-"),
                message_includes: *name != "siros-testkit",
                shipped: SHIPPED.contains(name) && parts.last() != Some(&"test_util.rs"),
            },
            ["crates", "siros-testkit", ..] => return None,
            _ if parts.contains(&"src") => Self {
                test_code: false,
                message_includes: true,
                shipped: false,
            },
            _ => return None,
        };
        (Path::new(file).extension().is_some_and(|e| e == "rs")).then_some(scope)
    }
}

/// Runs the rules over `root`.
pub(crate) fn run(root: &Path) -> Result<bool, Failure> {
    if !root.join("crates").is_dir() || !root.join("xtask").is_dir() {
        return Err(Failure::Read(format!(
            "{}: no crates and xtask directories",
            root.display()
        )));
    }
    let mut hits = Vec::new();
    let mut files = Vec::new();
    let mut names = Names::default();
    let mut gates = Gates::default();
    for top in ["crates", "xtask", "locales", "proving"] {
        if root.join(top).exists() {
            walk(root, top, &mut files, &mut hits);
        }
    }
    for file in &files {
        if is_message_source(file) && !message_source_exempt(file) {
            hits.push(Hit {
                file: file.clone(),
                line: 1,
                rule: "a message source outside the test app and a crate's tests/".to_owned(),
            });
        }
        if let Some(scope) = Scope::of(file) {
            scan(root, file, scope, &mut hits, &mut names, &mut gates);
        }
    }
    names.judge(&mut hits);
    gates.judge(&names, &mut hits);
    for hit in &hits {
        println!("{}:{}: {}", hit.file, hit.line, hit.rule);
    }
    println!("layout hits: {}", hits.len());
    Ok(hits.is_empty())
}

/// Lists the files under `dir` (a path from the root), sorted, past a `target` directory outside
/// a `src/` tree. A directory it cannot read and a symbolic link, which it does not follow, are
/// hits.
fn walk(root: &Path, dir: &str, files: &mut Vec<String>, hits: &mut Vec<Hit>) {
    let unread = |file: String, cause: String| Hit {
        file,
        line: 1,
        rule: format!("cannot read: {cause}"),
    };
    let entries = fs::read_dir(root.join(dir)).and_then(Iterator::collect::<Result<Vec<_>, _>>);
    let mut entries = match entries {
        Ok(entries) => entries,
        Err(cause) => return hits.push(unread(dir.to_owned(), cause.to_string())),
    };
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = format!("{dir}/{}", entry.file_name().to_string_lossy());
        match entry.file_type() {
            Ok(kind) if kind.is_dir() && is_build_output(&path) => {}
            Ok(kind) if kind.is_dir() => walk(root, &path, files, hits),
            Ok(kind) if kind.is_file() => files.push(path),
            Ok(_) => hits.push(unread(path, "a symbolic link".to_owned())),
            Err(cause) => hits.push(unread(path, cause.to_string())),
        }
    }
}

fn is_build_output(directory: &str) -> bool {
    let parts: Vec<&str> = directory.split('/').collect();
    parts.last() == Some(&"target") && !parts.contains(&"src")
}

/// Whether a path's last component ends in `.mf2` or `.ftl`, in any case; `.mf2` alone included.
fn is_message_source(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or_default();
    let name = name.to_ascii_lowercase();
    name.ends_with(".mf2") || name.ends_with(".ftl")
}

fn message_source_exempt(file: &str) -> bool {
    matches!(
        file.split('/').collect::<Vec<_>>().as_slice(),
        ["crates", _, "tests", ..] | ["crates", "siros-testkit", ..] | ["proving", ..]
    )
}

/// Reads and parses one source and walks its tree.
fn scan(
    root: &Path,
    file: &str,
    scope: Scope,
    hits: &mut Vec<Hit>,
    names: &mut Names,
    gates: &mut Gates,
) {
    let text = match fs::read_to_string(root.join(file)) {
        Ok(text) => text,
        Err(cause) => {
            return hits.push(Hit {
                file: file.to_owned(),
                line: 1,
                rule: format!("cannot read: {cause}"),
            });
        }
    };
    match syn::parse_file(&text) {
        Ok(tree) => {
            let module = module_of(file);
            names.enter(&module);
            let mut scanner = Scanner {
                file,
                scope,
                inline: Vec::new(),
                module,
                names,
                hits,
            };
            scanner.visit_file(&tree);
            gate::read(file, &tree, names, gates);
        }
        Err(cause) => hits.push(Hit {
            file: file.to_owned(),
            line: cause.span().start().line,
            rule: format!("does not parse: {cause}"),
        }),
    }
}

/// The walk of one source: `inline` holds the directories its enclosing inline modules add to a
/// `#[path]`, `module` the module it stands in.
struct Scanner<'a> {
    file: &'a str,
    scope: Scope,
    inline: Vec<String>,
    module: Vec<String>,
    names: &'a mut Names,
    hits: &'a mut Vec<Hit>,
}

impl Scanner<'_> {
    fn hit(&mut self, line: usize, rule: impl Into<String>) {
        self.hits.push(Hit {
            file: self.file.to_owned(),
            line,
            rule: rule.into(),
        });
    }

    /// An attribute's meta, its path then its arguments: the rules over test code.
    fn attribute(&mut self, meta: TokenStream, line: usize) {
        let trees: Vec<TokenTree> = meta.into_iter().collect();
        let Some((name, rest)) = path_head(&trees) else {
            return;
        };
        if let ("cfg_attr", [TokenTree::Group(group)]) = (name.as_str(), rest) {
            return self.conditional(group.stream(), line);
        }
        self.tokens(rest.iter().cloned().collect());
        if !self.scope.test_code {
            return;
        }
        if TEST_ATTRIBUTES.contains(&name.as_str()) {
            self.hit(line, format!("test attribute `{name}` under src/"));
            return;
        }
        match (name.as_str(), rest) {
            ("cfg", [TokenTree::Group(group)]) if names_test(group.stream()) => {
                self.hit(line, "a `cfg` naming test or doctest under src/");
            }
            ("path", [TokenTree::Punct(equals), TokenTree::Literal(written)])
                if equals.as_char() == '=' =>
            {
                if let Some(written) = string_value(written) {
                    self.path_attribute(&written, line);
                }
            }
            _ => {}
        }
    }

    /// `cfg_attr`'s arguments: its predicate, then the attributes it adds.
    fn conditional(&mut self, arguments: TokenStream, line: usize) {
        let parts = split_commas(arguments);
        let Some((predicate, added)) = parts.split_first() else {
            return;
        };
        if self.scope.test_code && names_test(predicate.iter().cloned().collect()) {
            self.hit(line, "a `cfg_attr` naming test or doctest under src/");
            return;
        }
        for attribute in added {
            self.attribute(attribute.iter().cloned().collect(), line);
        }
    }

    /// A `#[path]` value, read from this file's directory and its enclosing inline modules (the
    /// Reference's "The path attribute").
    fn path_attribute(&mut self, written: &str, line: usize) {
        let parts: Vec<&str> = self.file.split('/').collect();
        let from_src = parts.iter().position(|part| *part == "src").unwrap_or(0);
        let mut directory: Vec<&str> = parts
            .get(from_src + 1..parts.len().saturating_sub(1))
            .unwrap_or_default()
            .to_vec();
        let stem = parts.last().map_or("", |name| name.trim_end_matches(".rs"));
        let mod_rs = matches!(stem, "lib" | "main" | "mod") || directory == ["bin"];
        if !self.inline.is_empty() && !mod_rs {
            directory.push(stem);
        }
        directory.extend(self.inline.iter().map(String::as_str));
        if leaves_or_enters_tests(directory, written) {
            self.hit(
                line,
                format!("`#[path = {written:?}]` leaves src/ or enters tests/"),
            );
        }
    }

    /// A macro call by its path's last segment.
    fn macro_call(&mut self, name: &str, body: TokenStream, line: usize) {
        let included = joined_strings(body.clone());
        match name {
            "proptest" if self.scope.test_code => self.hit(line, "`proptest!` under src/"),
            "cfg" if self.scope.test_code && names_test(body.clone()) => {
                self.hit(line, "`cfg!` naming test or doctest under src/");
            }
            "include" | "include_str" | "include_bytes" => {
                if self.scope.test_code && under_tests(&included) {
                    self.hit(
                        line,
                        format!("`{name}!` of a path under tests/: {included}"),
                    );
                }
                if self.scope.message_includes && name != "include" && is_message_source(&included)
                {
                    self.hit(line, format!("`{name}!` of a message source: {included}"));
                }
            }
            _ => {}
        }
        self.tokens(body);
    }

    /// The rules over tokens `syn` leaves unparsed: attributes, macro calls and display calls.
    fn tokens(&mut self, stream: TokenStream) {
        let trees: Vec<TokenTree> = stream.into_iter().collect();
        for (at, tree) in trees.iter().enumerate() {
            let group = match tree {
                TokenTree::Group(group) => group,
                TokenTree::Ident(word) => {
                    self.token_item(word, &trees, at);
                    continue;
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => continue,
            };
            let before = trees.get(..at).unwrap_or_default();
            let line = group.span().start().line;
            match classify(before, group) {
                Tokens::Attribute => self.attribute(group.stream(), line),
                Tokens::Macro(name) => self.macro_call(&name, group.stream(), line),
                Tokens::Call(ty, function) => {
                    self.display_call(&ty, &function, group.stream(), line);
                    self.tokens(group.stream());
                }
                Tokens::Other => self.tokens(group.stream()),
            }
        }
    }

    /// A `struct`, `enum`, `impl` or `use` written in tokens, for I27.
    fn token_item(&mut self, word: &Ident, trees: &[TokenTree], at: usize) {
        let after = trees.get(at + 1..).unwrap_or_default();
        match word.to_string().as_str() {
            "struct" | "enum" => {
                let name = after.iter().find_map(|tree| match tree {
                    TokenTree::Ident(name) => Some(name),
                    _ => None,
                });
                if let Some(name) = name {
                    self.declare(metas_before(trees, at), name);
                }
            }
            "impl" => {
                if let Some((implemented, ty)) = implemented_paths(after) {
                    self.add_impl(ty, implemented);
                }
            }
            "use" => {
                let written: TokenStream = std::iter::once(TokenTree::Ident(word.clone()))
                    .chain(after.iter().cloned())
                    .take_while(|tree| !is_punct(tree, ';'))
                    .chain(std::iter::once(TokenTree::Punct(proc_macro2::Punct::new(
                        ';',
                        proc_macro2::Spacing::Alone,
                    ))))
                    .collect();
                if let Ok(item) = syn::parse2::<syn::ItemUse>(written) {
                    self.add_use(&item.tree);
                }
            }
            _ => {}
        }
    }

    /// A struct or enum for the names' table, and a shipped source's for I27.
    fn declare(&mut self, metas: Vec<TokenStream>, ident: &Ident) {
        if !self.scope.shipped {
            return self.names.add_item(&self.module, plain(ident));
        }
        let mut derives = Vec::new();
        for meta in metas {
            derived_paths(meta, &mut derives);
        }
        let at = (self.file, ident.span().start().line);
        self.names.add_type(&self.module, plain(ident), at, derives);
    }

    fn add_impl(&mut self, ty: Vec<String>, implemented: Vec<String>) {
        if self.scope.shipped {
            self.names.add_impl(&self.module, ty, implemented);
        }
    }

    fn add_use(&mut self, tree: &syn::UseTree) {
        self.names.add_use(&self.module, tree, &mut Vec::new());
    }

    /// I28: a call that builds a display text from a string literal.
    fn display_call(&mut self, ty: &str, function: &str, arguments: TokenStream, line: usize) {
        if self.scope.shipped
            && DISPLAY_CALLS.contains(&(ty, function))
            && holds_string_literal(arguments)
        {
            self.hit(line, format!("I28: `{ty}::{function}` of a literal"));
        }
    }
}

impl<'ast> Visit<'ast> for Scanner<'_> {
    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        let line = attribute.pound_token.span.start().line;
        self.attribute(attribute.meta.to_token_stream(), line);
    }

    fn visit_macro(&mut self, call: &'ast syn::Macro) {
        if let Some(last) = call.path.segments.last() {
            let name = plain(&last.ident);
            let line = last.ident.span().start().line;
            self.macro_call(&name, call.tokens.clone(), line);
        }
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(function) = call.func.as_ref() {
            let mut segments = function.path.segments.iter().rev();
            if let (Some(last), Some(ty)) = (segments.next(), segments.next()) {
                self.display_call(
                    &plain(&ty.ident),
                    &plain(&last.ident),
                    call.args.to_token_stream(),
                    last.ident.span().start().line,
                );
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        self.declare(metas_of(&item.attrs), &item.ident);
        visit::visit_item_struct(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        self.declare(metas_of(&item.attrs), &item.ident);
        visit::visit_item_enum(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if let (Some((implemented, _)), syn::Type::Path(ty)) = (&item.trait_, item.self_ty.as_ref())
        {
            self.add_impl(segments_of(&ty.path), segments_of(implemented));
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.add_use(&item.tree);
        visit::visit_item_use(self, item);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
        let name = plain(&item.ident);
        let given = item
            .rename
            .as_ref()
            .map_or_else(|| name.clone(), |(_, given)| plain(given));
        self.names.add_extern(&self.module, given, name);
        visit::visit_item_extern_crate(self, item);
    }

    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        for attribute in &module.attrs {
            self.visit_attribute(attribute);
        }
        let Some((_, items)) = &module.content else {
            return;
        };
        let depth = self.inline.len();
        self.inline.extend(inline_directories(module));
        self.module.push(plain(&module.ident));
        self.names.enter(&self.module);
        for item in items {
            self.visit_item(item);
        }
        drop(self.module.pop());
        self.inline.truncate(depth);
    }

    fn visit_item(&mut self, item: &'ast syn::Item) {
        if let syn::Item::Verbatim(tokens) = item {
            self.tokens(tokens.clone());
        }
        visit::visit_item(self, item);
    }

    fn visit_expr(&mut self, expression: &'ast syn::Expr) {
        if let syn::Expr::Verbatim(tokens) = expression {
            self.tokens(tokens.clone());
        }
        visit::visit_expr(self, expression);
    }

    fn visit_pat(&mut self, pattern: &'ast syn::Pat) {
        if let syn::Pat::Verbatim(tokens) = pattern {
            self.tokens(tokens.clone());
        }
        visit::visit_pat(self, pattern);
    }

    fn visit_type(&mut self, ty: &'ast syn::Type) {
        if let syn::Type::Verbatim(tokens) = ty {
            self.tokens(tokens.clone());
        }
        visit::visit_type(self, ty);
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if let syn::ImplItem::Verbatim(tokens) = item {
            self.tokens(tokens.clone());
        }
        visit::visit_impl_item(self, item);
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if let syn::TraitItem::Verbatim(tokens) = item {
            self.tokens(tokens.clone());
        }
        visit::visit_trait_item(self, item);
    }

    fn visit_foreign_item(&mut self, item: &'ast syn::ForeignItem) {
        if let syn::ForeignItem::Verbatim(tokens) = item {
            self.tokens(tokens.clone());
        }
        visit::visit_foreign_item(self, item);
    }
}

/// What a bracketed or parenthesised group in a macro body is, by the tokens before it.
enum Tokens {
    /// `#[...]` or `#![...]`.
    Attribute,
    /// `name!(...)`.
    Macro(String),
    /// `Type::function(...)`.
    Call(String, String),
    /// Anything else.
    Other,
}

fn classify(before: &[TokenTree], group: &Group) -> Tokens {
    match before {
        [.., TokenTree::Punct(pound)]
            if pound.as_char() == '#' && group.delimiter() == Delimiter::Bracket =>
        {
            Tokens::Attribute
        }
        [.., TokenTree::Punct(pound), TokenTree::Punct(bang)]
            if pound.as_char() == '#'
                && bang.as_char() == '!'
                && group.delimiter() == Delimiter::Bracket =>
        {
            Tokens::Attribute
        }
        [.., TokenTree::Ident(name), TokenTree::Punct(bang)] if bang.as_char() == '!' => {
            Tokens::Macro(plain(name))
        }
        [
            ..,
            TokenTree::Ident(ty),
            TokenTree::Punct(first),
            TokenTree::Punct(second),
            TokenTree::Ident(function),
        ] if first.as_char() == ':'
            && second.as_char() == ':'
            && group.delimiter() == Delimiter::Parenthesis =>
        {
            Tokens::Call(plain(ty), plain(function))
        }
        _ => Tokens::Other,
    }
}

/// An identifier without its raw mark: `r#test` names `test`.
fn plain(ident: &Ident) -> String {
    ident.unraw().to_string()
}

fn is_punct(tree: &TokenTree, punct: char) -> bool {
    matches!(tree, TokenTree::Punct(found) if found.as_char() == punct)
}

/// A path's segments.
fn segments_of(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| plain(&segment.ident))
        .collect()
}

fn metas_of(attributes: &[syn::Attribute]) -> Vec<TokenStream> {
    attributes
        .iter()
        .map(|attribute| attribute.meta.to_token_stream())
        .collect()
}

/// The attributes written before the item keyword at `at`, past its visibility.
fn metas_before(trees: &[TokenTree], at: usize) -> Vec<TokenStream> {
    let mut before = trees.get(..at).unwrap_or_default();
    if let [head @ .., TokenTree::Ident(public), TokenTree::Group(_)] = before
        && public == "pub"
    {
        before = head;
    } else if let [head @ .., TokenTree::Ident(public)] = before
        && public == "pub"
    {
        before = head;
    }
    let mut metas = Vec::new();
    while let [head @ .., TokenTree::Punct(pound), TokenTree::Group(group)] = before
        && pound.as_char() == '#'
    {
        metas.push(group.stream());
        before = head;
    }
    metas
}

fn is_brace(tree: &TokenTree) -> bool {
    matches!(tree, TokenTree::Group(group) if group.delimiter() == Delimiter::Brace)
}

/// The paths of `Trait for Type` in the tokens after `impl`, before its body.
fn implemented_paths(after: &[TokenTree]) -> Option<(Vec<String>, Vec<String>)> {
    let head: Vec<&TokenTree> = after.iter().take_while(|tree| !is_brace(tree)).collect();
    let split = head
        .iter()
        .position(|tree| matches!(tree, TokenTree::Ident(word) if word == "for"))?;
    let implemented = head.get(..split)?;
    let ty = head.get(split + 1..)?;
    let implemented = last_path(implemented);
    let ty = first_path(ty);
    (!implemented.is_empty() && !ty.is_empty()).then_some((implemented, ty))
}

/// The path that ends a token run.
fn last_path(trees: &[&TokenTree]) -> Vec<String> {
    let mut path = Vec::new();
    for tree in trees.iter().rev() {
        match tree {
            TokenTree::Ident(segment) => path.push(plain(segment)),
            TokenTree::Punct(punct) if matches!(punct.as_char(), ':' | '$') => {}
            _ => break,
        }
    }
    path.reverse();
    path
}

/// The path that starts a token run.
fn first_path(trees: &[&TokenTree]) -> Vec<String> {
    let mut path = Vec::new();
    for tree in trees {
        match tree {
            TokenTree::Ident(segment) => path.push(plain(segment)),
            TokenTree::Punct(punct) if matches!(punct.as_char(), ':' | '$') => {}
            _ => break,
        }
    }
    path
}

/// A path's last segment, and the tokens after the path.
fn path_head(trees: &[TokenTree]) -> Option<(String, &[TokenTree])> {
    let mut rest = trees;
    let mut last = None;
    loop {
        match rest {
            [TokenTree::Punct(first), TokenTree::Punct(second), tail @ ..]
                if first.as_char() == ':' && second.as_char() == ':' =>
            {
                rest = tail;
            }
            [TokenTree::Ident(segment), tail @ ..] => {
                last = Some(plain(segment));
                rest = tail;
            }
            _ => return last.map(|name| (name, rest)),
        }
    }
}

/// The paths an attribute derives, through `cfg_attr`.
fn derived_paths(meta: TokenStream, paths: &mut Vec<Vec<String>>) {
    let trees: Vec<TokenTree> = meta.into_iter().collect();
    let Some((name, [TokenTree::Group(group)])) = path_head(&trees) else {
        return;
    };
    match name.as_str() {
        "derive" => paths.extend(split_commas(group.stream()).iter().map(|part| {
            part.iter()
                .filter_map(|tree| match tree {
                    TokenTree::Ident(segment) => Some(plain(segment)),
                    _ => None,
                })
                .collect()
        })),
        "cfg_attr" => {
            for added in split_commas(group.stream()).iter().skip(1) {
                derived_paths(added.iter().cloned().collect(), paths);
            }
        }
        _ => {}
    }
}

/// A comma-separated list's items.
fn split_commas(stream: TokenStream) -> Vec<Vec<TokenTree>> {
    let mut parts = vec![Vec::new()];
    for tree in stream {
        match (&tree, parts.last_mut()) {
            (TokenTree::Punct(comma), _) if comma.as_char() == ',' => parts.push(Vec::new()),
            (_, Some(part)) => part.push(tree),
            (_, None) => {}
        }
    }
    parts
}

/// Whether a `cfg` predicate names `test` or `doctest`, at any depth of `all`, `any` and `not`.
fn names_test(predicate: TokenStream) -> bool {
    split_commas(predicate)
        .iter()
        .any(|part| match part.as_slice() {
            [TokenTree::Ident(name)] => matches!(plain(name).as_str(), "test" | "doctest"),
            [TokenTree::Ident(name), TokenTree::Group(inner)] => {
                matches!(plain(name).as_str(), "all" | "any" | "not") && names_test(inner.stream())
            }
            _ => false,
        })
}

/// The string literals a macro's arguments hold, in order, at any depth, joined: `concat!`'s
/// parts read as one path.
fn joined_strings(stream: TokenStream) -> String {
    let mut joined = String::new();
    for tree in stream {
        match tree {
            TokenTree::Group(group) => joined.push_str(&joined_strings(group.stream())),
            TokenTree::Literal(literal) => {
                joined.push_str(&string_value(&literal).unwrap_or_default());
            }
            TokenTree::Ident(_) | TokenTree::Punct(_) => {}
        }
    }
    joined
}

fn holds_string_literal(stream: TokenStream) -> bool {
    stream.into_iter().any(|tree| match tree {
        TokenTree::Group(group) => holds_string_literal(group.stream()),
        TokenTree::Literal(literal) => string_value(&literal).is_some(),
        TokenTree::Ident(_) | TokenTree::Punct(_) => false,
    })
}

/// A string literal's value, its escapes read.
fn string_value(literal: &Literal) -> Option<String> {
    match syn::Lit::new(literal.clone()) {
        syn::Lit::Str(text) => Some(text.value()),
        _ => None,
    }
}

fn under_tests(path: &str) -> bool {
    path.split(['/', '\\']).any(|part| part == "tests")
}

/// Whether `written`, read from `directory` under `src/`, leaves `src/` or names a `tests`
/// directory.
fn leaves_or_enters_tests<'a>(mut directory: Vec<&'a str>, written: &'a str) -> bool {
    if written.starts_with(['/', '\\']) || written.contains(':') {
        return true;
    }
    for part in written.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                if directory.pop().is_none() {
                    return true;
                }
            }
            name => directory.push(name),
        }
    }
    directory.contains(&"tests")
}

/// The directories an inline module adds to a `#[path]` inside it: its own `#[path]`'s, else its
/// name.
fn inline_directories(module: &syn::ItemMod) -> Vec<String> {
    let written = module
        .attrs
        .iter()
        .find_map(|attribute| match &attribute.meta {
            syn::Meta::NameValue(pair) if pair.path.is_ident("path") => match &pair.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(text),
                    ..
                }) => Some(text.value()),
                _ => None,
            },
            _ => None,
        });
    written.map_or_else(
        || vec![plain(&module.ident)],
        |path| path.split('/').map(str::to_owned).collect(),
    )
}
