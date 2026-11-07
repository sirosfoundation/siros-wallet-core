//! The rule over `feature = "test-util"` (AGENTS.md, Tests): the feature holds doubles of the
//! crate's extension points, written with its public API alone.
//!
//! A gate stands on a whole item, a module or a file, at any depth of a `cfg` predicate. The types
//! it declares are the doubles'. Under it, the rule refuses:
//!
//! - an inherent `impl` of a type outside the gate, and a trait `impl` on such a type with private
//!   fields;
//! - a `pub` item whose signature or type names such a type, a trait `impl`'s methods apart: the
//!   extension point fixes those;
//! - a free `pub fn`, a `pub const` and a `pub static`: a double is a type with its `impl`s;
//! - a value of such a type made by its literal or its tuple constructor;
//! - a call of a function outside the gate with no `pub`;
//! - a `pub use` of an item outside the gate;
//! - what it cannot read: a glob `pub use`, a macro call in item position, a `#[path]` on a module.
//!
//! It refuses a gate anywhere else: on an associated item of an `impl` or a `trait` outside the
//! gate, on a field or another part of an item, in a `cfg_attr` or in a macro's tokens.

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use quote::ToTokens;
use rustc_hash::{FxHashMap, FxHashSet};
use syn::visit::{self, Visit};

use super::names::{Global, Names, module_of};
use super::{Hit, plain, segments_of, string_value};

const FEATURE: &str = "test-util";

/// A struct, enum or union a source declares.
struct Declared {
    module: Global,
    name: String,
    /// A struct with a field outside the public API, or a type outside it itself.
    restricted: bool,
    /// An enum, whose variants' paths extend its own.
    enumerated: bool,
    gated: bool,
}

/// A function or constant a source declares, outside a trait `impl`.
struct Callable {
    module: Global,
    /// The `impl`'s type as written, for an associated item.
    owner: Option<Vec<String>>,
    name: String,
    public: bool,
    gated: bool,
    /// The paths its return type or its type names.
    mentions: Vec<Vec<String>>,
}

/// What one place of a source says, for the rule to judge.
enum Kind {
    /// A gate where a gate cannot stand.
    Placement(String),
    /// Under a gate, what the rule cannot read.
    Unread(String),
    /// An inherent `impl`, with its type as written.
    Inherent(Vec<String>),
    /// A trait `impl`, with its type as written.
    TraitImpl(Vec<String>),
    /// The paths a `pub` item's signature or type names.
    Signature(Vec<Vec<String>>),
    /// A path in value position, or a literal's.
    Value(Vec<String>),
    /// A method call's name.
    Method(String),
    /// A `pub` function, constant or static outside an `impl`.
    Fixture,
    /// A `pub use`'s path.
    Reexport(Vec<String>),
}

struct Fact {
    file: String,
    line: usize,
    module: Global,
    gated: bool,
    /// The item it stands in: an item gives one hit, at its first refused place.
    item: usize,
    label: String,
    kind: Kind,
}

/// What every source says about the gates, judged once all are read: a `mod` in one file gates
/// another.
#[derive(Default)]
pub(super) struct Gates {
    /// The modules declared under a gate, each with what it holds.
    modules: Vec<Global>,
    types: Vec<Declared>,
    callables: Vec<Callable>,
    facts: Vec<Fact>,
    items: usize,
}

/// Reads one source's tree into `gates` and `names`.
pub(super) fn read(file: &str, tree: &syn::File, names: &mut Names, gates: &mut Gates) {
    let mut reader = Reader {
        file,
        module: module_of(file),
        gated: false,
        item: 0,
        label: String::new(),
        self_ty: None,
        inherent: false,
        in_item: false,
        owed: 0,
        names,
        gates,
    };
    reader.new_item();
    reader.visit_file(tree);
}

/// The walk of one source.
struct Reader<'a> {
    file: &'a str,
    module: Vec<String>,
    gated: bool,
    item: usize,
    label: String,
    /// The enclosing `impl`'s type as written.
    self_ty: Option<Vec<String>>,
    /// Whether that `impl` is inherent.
    inherent: bool,
    /// Whether the walk stands inside an item other than a module.
    in_item: bool,
    /// The `cfg` gates on enclosing items that syn's walk has yet to visit.
    owed: usize,
    names: &'a mut Names,
    gates: &'a mut Gates,
}

impl Reader<'_> {
    fn new_item(&mut self) {
        self.gates.items += 1;
        self.item = self.gates.items;
    }

    fn fact(&mut self, line: usize, kind: Kind) {
        self.gates.facts.push(Fact {
            file: self.file.to_owned(),
            line,
            module: self.module.clone(),
            gated: self.gated,
            item: self.item,
            label: self.label.clone(),
            kind,
        });
    }

    /// A path with its `Self` read as the enclosing `impl`'s type.
    fn written(&self, path: Vec<String>) -> Vec<String> {
        match (path.split_first(), &self.self_ty) {
            (Some((first, rest)), Some(own)) if first == "Self" => {
                own.iter().chain(rest).cloned().collect()
            }
            _ => path,
        }
    }

    /// The paths a type names, its `Self` read.
    fn mentions(&self, visit_it: impl FnOnce(&mut Mentions)) -> Vec<Vec<String>> {
        let mut found = Mentions(Vec::new());
        visit_it(&mut found);
        found.0.into_iter().map(|path| self.written(path)).collect()
    }

    /// Runs `body` as the item with these attributes, then restores the walk's state.
    fn within(&mut self, attrs: &[syn::Attribute], label: String, body: impl FnOnce(&mut Self)) {
        let gates = attrs.iter().filter(|attribute| is_gate(attribute)).count();
        let saved = (
            self.gated,
            self.item,
            std::mem::replace(&mut self.label, label),
            self.self_ty.clone(),
            self.inherent,
            self.in_item,
        );
        self.owed += gates;
        self.gated |= gates > 0;
        body(self);
        (
            self.gated,
            self.item,
            self.label,
            self.self_ty,
            self.inherent,
            self.in_item,
        ) = saved;
    }

    /// An associated item: a gate on it stands only inside a gate.
    fn associated(&mut self, attrs: &[syn::Attribute], name: String, body: impl FnOnce(&mut Self)) {
        let label = self.self_ty.as_ref().map_or_else(
            || name.clone(),
            |owner| format!("{}::{name}", owner.join("::")),
        );
        let gate = attrs.iter().find(|attribute| is_gate(attribute));
        let refused = gate.filter(|_| !self.gated).map(gate_line);
        self.within(attrs, label, |this| {
            if let Some(line) = refused {
                this.new_item();
                this.fact(
                    line,
                    Kind::Placement("a gate on an associated item outside the gate".to_owned()),
                );
            }
            body(this);
        });
    }

    /// A function or constant outside a trait `impl`.
    fn declared_value(
        &mut self,
        name: &syn::Ident,
        vis: &syn::Visibility,
        mentions: Vec<Vec<String>>,
    ) {
        let owner = self.self_ty.clone().filter(|_| self.inherent);
        let free = owner.is_none();
        if free {
            self.names.add_item(&self.module, plain(name));
        }
        self.gates.callables.push(Callable {
            module: self.module.clone(),
            owner,
            name: plain(name),
            public: is_public(vis),
            gated: self.gated,
            mentions: mentions.clone(),
        });
        if !matches!(vis, syn::Visibility::Inherited) {
            self.fact(name.span().start().line, Kind::Signature(mentions));
        }
        if free && is_public(vis) {
            self.fact(name.span().start().line, Kind::Fixture);
        }
    }

    fn declared_type(&mut self, ident: &syn::Ident, restricted: bool, enumerated: bool) {
        self.gates.types.push(Declared {
            module: self.module.clone(),
            name: plain(ident),
            restricted,
            enumerated,
            gated: self.gated,
        });
    }

    fn reexports(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>, line: usize) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(plain(&path.ident));
                self.reexports(&path.tree, prefix, line);
                drop(prefix.pop());
            }
            syn::UseTree::Name(syn::UseName { ident })
            | syn::UseTree::Rename(syn::UseRename { ident, .. }) => {
                let mut path = prefix.clone();
                if ident != "self" {
                    path.push(plain(ident));
                }
                self.fact(line, Kind::Reexport(path));
            }
            syn::UseTree::Glob(_) => {
                self.fact(
                    line,
                    Kind::Unread(format!("a glob re-export of `{}`", prefix.join("::"))),
                );
            }
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.reexports(item, prefix, line);
                }
            }
        }
    }

    /// Tokens `syn` leaves unparsed: a gate among them cannot be read, and what they make counts.
    fn tokens(&mut self, stream: &TokenStream, line: usize, what: &str) {
        if mentions_feature(stream.clone()) {
            self.fact(line, Kind::Placement(format!("a gate in {what}")));
        }
        self.token_values(stream.clone());
    }

    /// The paths, literals, method calls and type declarations a token run holds.
    fn token_values(&mut self, stream: TokenStream) {
        let trees: Vec<TokenTree> = stream.into_iter().collect();
        let mut at = 0;
        while let Some(tree) = trees.get(at) {
            at += 1;
            match tree {
                TokenTree::Group(group) => self.token_values(group.stream()),
                TokenTree::Punct(dot) if dot.as_char() == '.' => {
                    if let [TokenTree::Ident(name), TokenTree::Group(_), ..] =
                        trees.get(at..).unwrap_or_default()
                    {
                        self.fact(name.span().start().line, Kind::Method(plain(name)));
                        at += 1;
                    }
                }
                TokenTree::Ident(word) => {
                    let line = word.span().start().line;
                    let after = trees.get(at..).unwrap_or_default();
                    if let ("struct" | "enum" | "union", [TokenTree::Ident(name), ..]) =
                        (plain(word).as_str(), after)
                    {
                        self.declared_type(name, true, false);
                        at += 1;
                        continue;
                    }
                    let (path, rest) = token_path(plain(word), after);
                    at = trees.len() - rest.len();
                    let called = matches!(
                        rest.first(),
                        Some(TokenTree::Group(group))
                            if matches!(group.delimiter(), Delimiter::Brace | Delimiter::Parenthesis)
                    );
                    if path.len() > 1 || called {
                        let path = self.written(path);
                        self.fact(line, Kind::Value(path));
                    }
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }
}

/// The path that `first` starts, and the tokens after it.
fn token_path(first: String, mut rest: &[TokenTree]) -> (Vec<String>, &[TokenTree]) {
    let mut path = vec![first];
    while let [
        TokenTree::Punct(one),
        TokenTree::Punct(two),
        TokenTree::Ident(segment),
        tail @ ..,
    ] = rest
        && one.as_char() == ':'
        && two.as_char() == ':'
    {
        path.push(plain(segment));
        rest = tail;
    }
    (path, rest)
}

/// Whether tokens hold `feature = "test-util"`, at any depth.
fn mentions_feature(stream: TokenStream) -> bool {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    trees.iter().enumerate().any(|(at, tree)| match tree {
        TokenTree::Group(group) => mentions_feature(group.stream()),
        TokenTree::Ident(word) if word == "feature" => matches!(
            trees.get(at + 1..at + 3),
            Some([TokenTree::Punct(equals), TokenTree::Literal(value)])
                if equals.as_char() == '=' && string_value(value).as_deref() == Some(FEATURE)
        ),
        _ => false,
    })
}

fn attribute_name(attribute: &syn::Attribute) -> Option<String> {
    let last = attribute.path().segments.last()?;
    Some(plain(&last.ident))
}

fn is_gate(attribute: &syn::Attribute) -> bool {
    attribute_name(attribute).as_deref() == Some("cfg")
        && mentions_feature(attribute.meta.to_token_stream())
}

fn gate_line(attribute: &syn::Attribute) -> usize {
    attribute.pound_token.span.start().line
}

fn has_attribute(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs
        .iter()
        .any(|attribute| attribute.path().is_ident(name))
}

fn is_public(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_))
}

/// A type's path through references and parentheses.
fn type_path(ty: &syn::Type) -> Option<Vec<String>> {
    match ty {
        syn::Type::Path(path) => Some(segments_of(&path.path)),
        syn::Type::Reference(reference) => type_path(&reference.elem),
        syn::Type::Paren(inner) => type_path(&inner.elem),
        syn::Type::Group(inner) => type_path(&inner.elem),
        _ => None,
    }
}

/// An item's attributes and the name a hit gives it.
fn item_parts(item: &syn::Item) -> (&[syn::Attribute], String) {
    match item {
        syn::Item::Const(item) => (&item.attrs, plain(&item.ident)),
        syn::Item::Enum(item) => (&item.attrs, plain(&item.ident)),
        syn::Item::ExternCrate(item) => (&item.attrs, plain(&item.ident)),
        syn::Item::Fn(item) => (&item.attrs, plain(&item.sig.ident)),
        syn::Item::ForeignMod(item) => (&item.attrs, "extern".to_owned()),
        syn::Item::Impl(item) => (&item.attrs, impl_label(item)),
        syn::Item::Macro(item) => {
            let name = item
                .ident
                .as_ref()
                .map_or_else(|| macro_name(&item.mac), plain);
            (&item.attrs, format!("{name}!"))
        }
        syn::Item::Mod(item) => (&item.attrs, plain(&item.ident)),
        syn::Item::Static(item) => (&item.attrs, plain(&item.ident)),
        syn::Item::Struct(item) => (&item.attrs, plain(&item.ident)),
        syn::Item::Trait(item) => (&item.attrs, plain(&item.ident)),
        syn::Item::TraitAlias(item) => (&item.attrs, plain(&item.ident)),
        syn::Item::Type(item) => (&item.attrs, plain(&item.ident)),
        syn::Item::Union(item) => (&item.attrs, plain(&item.ident)),
        syn::Item::Use(item) => (
            &item.attrs,
            format!(
                "use {}",
                item.tree.to_token_stream().to_string().replace(' ', "")
            ),
        ),
        _ => (&[], String::new()),
    }
}

fn macro_name(call: &syn::Macro) -> String {
    call.path
        .segments
        .last()
        .map_or_else(String::new, |last| plain(&last.ident))
}

/// The line of a path's last segment.
fn path_line(path: &syn::Path) -> usize {
    path.segments
        .last()
        .map_or(1, |last| last.ident.span().start().line)
}

fn impl_label(item: &syn::ItemImpl) -> String {
    let ty = type_path(&item.self_ty).map_or_else(|| "?".to_owned(), |path| path.join("::"));
    match &item.trait_ {
        Some((implemented, _)) => {
            format!("impl {} for {ty}", segments_of(implemented).join("::"))
        }
        None => format!("impl {ty}"),
    }
}

/// The paths a type names, its arguments included.
struct Mentions(Vec<Vec<String>>);

impl<'ast> Visit<'ast> for Mentions {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.0.push(segments_of(path));
        visit::visit_path(self, path);
    }
}

impl<'ast> Visit<'ast> for Reader<'_> {
    fn visit_file(&mut self, file: &'ast syn::File) {
        let gates = file.attrs.iter().filter(|a| is_gate(a)).count();
        if gates > 0 {
            self.owed += gates;
            self.gated = true;
            self.gates.modules.push(self.module.clone());
        }
        visit::visit_file(self, file);
    }

    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        if !mentions_feature(attribute.meta.to_token_stream()) {
            return;
        }
        let line = gate_line(attribute);
        match attribute_name(attribute).as_deref() {
            Some("cfg") if self.owed > 0 => self.owed -= 1,
            Some("cfg") => self.fact(
                line,
                Kind::Placement("a gate on a part of an item".to_owned()),
            ),
            Some("cfg_attr") => self.fact(line, Kind::Placement("a `cfg_attr` gate".to_owned())),
            _ => {}
        }
    }

    fn visit_item(&mut self, item: &'ast syn::Item) {
        let (attrs, label) = item_parts(item);
        self.within(attrs, label, |this| {
            if !this.in_item {
                this.new_item();
            }
            this.in_item |= !matches!(item, syn::Item::Mod(_));
            this.self_ty = None;
            this.inherent = false;
            if let syn::Item::Verbatim(tokens) = item {
                this.tokens(tokens, 1, "an item syn leaves unparsed");
            }
            visit::visit_item(this, item);
        });
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        let restricted = !is_public(&item.vis)
            || has_attribute(&item.attrs, "non_exhaustive")
            || item.fields.iter().any(|field| !is_public(&field.vis));
        self.declared_type(&item.ident, restricted, false);
        visit::visit_item_struct(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        let restricted = !is_public(&item.vis)
            || item
                .variants
                .iter()
                .any(|variant| has_attribute(&variant.attrs, "non_exhaustive"));
        self.declared_type(&item.ident, restricted, true);
        visit::visit_item_enum(self, item);
    }

    fn visit_item_union(&mut self, item: &'ast syn::ItemUnion) {
        self.names.add_item(&self.module, plain(&item.ident));
        self.declared_type(&item.ident, true, false);
        visit::visit_item_union(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if let Some(target) = type_path(&item.ty) {
            self.names
                .add_alias(&self.module, plain(&item.ident), target);
        }
        visit::visit_item_type(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let mentions = self.mentions(|found| found.visit_return_type(&item.sig.output));
        self.declared_value(&item.sig.ident, &item.vis, mentions);
        visit::visit_item_fn(self, item);
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        let mentions = self.mentions(|found| found.visit_type(&item.ty));
        self.declared_value(&item.ident, &item.vis, mentions);
        visit::visit_item_const(self, item);
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        let mentions = self.mentions(|found| found.visit_type(&item.ty));
        self.declared_value(&item.ident, &item.vis, mentions);
        visit::visit_item_static(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let line = item.impl_token.span.start().line;
        let ty = type_path(&item.self_ty);
        match (&item.trait_, &ty) {
            (None, Some(path)) => self.fact(line, Kind::Inherent(path.clone())),
            (None, None) => self.fact(
                line,
                Kind::Unread("an inherent `impl` of a type with no path".to_owned()),
            ),
            (Some(_), Some(path)) => self.fact(line, Kind::TraitImpl(path.clone())),
            (Some(_), None) => {}
        }
        self.self_ty = ty;
        self.inherent = item.trait_.is_none();
        visit::visit_item_impl(self, item);
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        self.fact(
            path_line(&item.mac.path),
            Kind::Unread("a macro in item position under the gate".to_owned()),
        );
        visit::visit_item_macro(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if !matches!(item.vis, syn::Visibility::Inherited) {
            let line = item.use_token.span.start().line;
            self.reexports(&item.tree, &mut Vec::new(), line);
        }
        visit::visit_item_use(self, item);
    }

    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        let mut inner = self.module.clone();
        inner.push(plain(&module.ident));
        if self.gated {
            self.gates.modules.push(inner.clone());
        }
        if has_attribute(&module.attrs, "path") {
            self.fact(
                module.mod_token.span.start().line,
                Kind::Unread("a `#[path]` module under the gate".to_owned()),
            );
        }
        let outer = std::mem::replace(&mut self.module, inner);
        visit::visit_item_mod(self, module);
        self.module = outer;
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let (attrs, name): (&[syn::Attribute], String) = match item {
            syn::ImplItem::Const(item) => (&item.attrs, plain(&item.ident)),
            syn::ImplItem::Fn(item) => (&item.attrs, plain(&item.sig.ident)),
            syn::ImplItem::Type(item) => (&item.attrs, plain(&item.ident)),
            syn::ImplItem::Macro(item) => (&item.attrs, macro_name(&item.mac)),
            _ => (&[], String::new()),
        };
        self.associated(attrs, name, |this| {
            if let syn::ImplItem::Verbatim(tokens) = item {
                this.tokens(tokens, 1, "an associated item syn leaves unparsed");
            }
            visit::visit_impl_item(this, item);
        });
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if self.inherent {
            let mentions = self.mentions(|found| found.visit_return_type(&item.sig.output));
            self.declared_value(&item.sig.ident, &item.vis, mentions);
        }
        visit::visit_impl_item_fn(self, item);
    }

    fn visit_impl_item_const(&mut self, item: &'ast syn::ImplItemConst) {
        if self.inherent {
            let mentions = self.mentions(|found| found.visit_type(&item.ty));
            self.declared_value(&item.ident, &item.vis, mentions);
        }
        visit::visit_impl_item_const(self, item);
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let (attrs, name): (&[syn::Attribute], String) = match item {
            syn::TraitItem::Const(item) => (&item.attrs, plain(&item.ident)),
            syn::TraitItem::Fn(item) => (&item.attrs, plain(&item.sig.ident)),
            syn::TraitItem::Type(item) => (&item.attrs, plain(&item.ident)),
            syn::TraitItem::Macro(item) => (&item.attrs, macro_name(&item.mac)),
            _ => (&[], String::new()),
        };
        self.associated(attrs, name, |this| {
            if let syn::TraitItem::Verbatim(tokens) = item {
                this.tokens(tokens, 1, "a trait item syn leaves unparsed");
            }
            visit::visit_trait_item(this, item);
        });
    }

    fn visit_expr(&mut self, expression: &'ast syn::Expr) {
        if let syn::Expr::Verbatim(tokens) = expression {
            self.tokens(tokens, 1, "an expression syn leaves unparsed");
        }
        visit::visit_expr(self, expression);
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        let path = self.written(segments_of(&expression.path));
        self.fact(path_line(&expression.path), Kind::Value(path));
        visit::visit_expr_path(self, expression);
    }

    fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
        let path = self.written(segments_of(&expression.path));
        self.fact(path_line(&expression.path), Kind::Value(path));
        visit::visit_expr_struct(self, expression);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.fact(
            call.method.span().start().line,
            Kind::Method(plain(&call.method)),
        );
        visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, call: &'ast syn::Macro) {
        let what = format!("the tokens of `{}!`", macro_name(call));
        self.tokens(&call.tokens, path_line(&call.path), &what);
    }
}

/// What the table knows of a type.
#[derive(Clone, Copy)]
struct TypeFacts {
    restricted: bool,
    enumerated: bool,
    gated: bool,
}

/// What the table knows of a function or constant.
#[derive(Clone, Copy)]
struct CallFacts {
    public: bool,
    gated: bool,
}

/// What a method's name can reach in a crate, over its inherent methods of that name.
#[derive(Clone, Copy, Default)]
struct MethodFacts {
    reachable: bool,
    makes_restricted: bool,
}

/// The whole workspace's types and functions by their paths.
struct Table<'a> {
    names: &'a Names,
    modules: &'a [Global],
    types: FxHashMap<Global, TypeFacts>,
    callables: FxHashMap<Global, CallFacts>,
    methods: FxHashMap<(String, String), MethodFacts>,
}

impl Table<'_> {
    fn under_gate(&self, module: &[String]) -> bool {
        self.modules.iter().any(|gated| module.starts_with(gated))
    }

    /// A type's path, read in `module`, when it names a type outside the gate with private fields.
    fn restricted(&self, module: &[String], path: &[String]) -> bool {
        self.names.paths(module, path).iter().any(|candidate| {
            self.types
                .get(candidate)
                .is_some_and(|ty| ty.restricted && !ty.gated)
        })
    }

    fn declared_under_gate(&self, module: &[String], path: &[String]) -> bool {
        self.names
            .paths(module, path)
            .iter()
            .any(|candidate| self.types.get(candidate).is_some_and(|ty| ty.gated))
    }

    /// Why a path in value position leaves the public API.
    fn value(&self, module: &[String], path: &[String]) -> Option<String> {
        let shown = path.join("::");
        self.names.paths(module, path).iter().find_map(|candidate| {
            if let Some(callable) = self.callables.get(candidate) {
                return (!callable.public && !callable.gated)
                    .then(|| format!("uses `{shown}`, outside the public API"));
            }
            let ty = match self.types.get(candidate) {
                Some(ty) => *ty,
                None => {
                    let (_, parent) = candidate.split_last()?;
                    let parent = self.types.get(parent)?;
                    if !parent.enumerated {
                        return None;
                    }
                    *parent
                }
            };
            (ty.restricted && !ty.gated)
                .then(|| format!("makes a value of `{shown}`, a type with private fields"))
        })
    }

    /// Why a `pub use` leaves the gate.
    fn reexport(&self, module: &[String], path: &[String]) -> Option<String> {
        let outside = self.names.paths(module, path).iter().any(|candidate| {
            self.types.get(candidate).is_some_and(|ty| !ty.gated)
                || self.callables.get(candidate).is_some_and(|it| !it.gated)
                || (self.names.holds_module(candidate) && !self.under_gate(candidate))
        });
        outside.then(|| {
            format!(
                "re-exports `{}`, declared outside the gate",
                path.join("::")
            )
        })
    }

    fn refusal(&self, fact: &Fact) -> Option<String> {
        let module = &fact.module;
        let gated = fact.gated || self.under_gate(module);
        match &fact.kind {
            Kind::Placement(rule) => Some(rule.clone()),
            _ if !gated => None,
            Kind::Unread(rule) => Some(rule.clone()),
            Kind::Inherent(ty) => (!self.declared_under_gate(module, ty))
                .then(|| "an inherent `impl` of a type outside the gate".to_owned()),
            Kind::TraitImpl(ty) => self
                .restricted(module, ty)
                .then(|| "a trait `impl` on a type with private fields".to_owned()),
            Kind::Signature(mentions) => mentions
                .iter()
                .find(|path| self.restricted(module, path))
                .map(|path| {
                    format!(
                        "a `pub` item that gives `{}`, a type with private fields",
                        path.join("::")
                    )
                }),
            Kind::Value(path) => self.value(module, path),
            Kind::Method(name) => {
                let krate = module.first().cloned().unwrap_or_default();
                self.methods
                    .get(&(krate, name.clone()))
                    .filter(|method| !method.reachable && method.makes_restricted)
                    .map(|_| format!("calls `.{name}`, outside the public API"))
            }
            Kind::Fixture => Some("a `pub` item that is no type: a double is a type".to_owned()),
            Kind::Reexport(path) => self.reexport(module, path),
        }
    }
}

impl Gates {
    /// Builds the table the facts read.
    fn table<'a>(&'a self, names: &'a Names) -> Table<'a> {
        let mut table = Table {
            names,
            modules: &self.modules,
            types: FxHashMap::default(),
            callables: FxHashMap::default(),
            methods: FxHashMap::default(),
        };
        for declared in &self.types {
            let mut path = declared.module.clone();
            path.push(declared.name.clone());
            let facts = TypeFacts {
                restricted: declared.restricted,
                enumerated: declared.enumerated,
                gated: declared.gated || table.under_gate(&declared.module),
            };
            let merged = table.types.get(&path).map_or(facts, |known| TypeFacts {
                restricted: known.restricted || facts.restricted,
                enumerated: known.enumerated || facts.enumerated,
                gated: known.gated && facts.gated,
            });
            *table.types.entry(path).or_insert(merged) = merged;
        }
        for callable in &self.callables {
            let facts = CallFacts {
                public: callable.public,
                gated: callable.gated || table.under_gate(&callable.module),
            };
            let owners = match &callable.owner {
                None => vec![callable.module.clone()],
                Some(owner) => names.paths(&callable.module, owner),
            };
            for mut path in owners {
                path.push(callable.name.clone());
                *table.callables.entry(path).or_insert(facts) = facts;
            }
        }
        for callable in self.callables.iter().filter(|it| it.owner.is_some()) {
            let krate = callable.module.first().cloned().unwrap_or_default();
            let makes = callable
                .mentions
                .iter()
                .any(|path| table.restricted(&callable.module, path));
            let gated = callable.gated || table.under_gate(&callable.module);
            let method = table
                .methods
                .entry((krate, callable.name.clone()))
                .or_default();
            method.reachable |= callable.public || gated;
            method.makes_restricted |= makes;
        }
        table
    }

    /// The hits of the rule: each refused item once, at its first refused place.
    pub(super) fn judge(&self, names: &Names, hits: &mut Vec<Hit>) {
        let table = self.table(names);
        let mut refused: FxHashSet<usize> = FxHashSet::default();
        for fact in &self.facts {
            let Some(rule) = table.refusal(fact) else {
                continue;
            };
            if refused.insert(fact.item) {
                hits.push(Hit {
                    file: fact.file.clone(),
                    line: fact.line,
                    rule: format!("{FEATURE}: `{}`: {rule}", fact.label),
                });
            }
        }
    }
}
