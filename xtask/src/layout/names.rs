//! The names I27 and I28 read: each module's `use` items, and the types, `impl`s and struct
//! expressions the shipped crates write, resolved along Rust's path rules (the Reference's "Use
//! declarations" and "Paths"). A `use` or an item in a function body counts in its module. The
//! test-util rule reads the same table, over every crate's sources.

use rustc_hash::FxHashMap;

use super::Hit;

/// A path from a crate's name: the crate's segment joins its name's words with `_`.
pub(super) type Global = Vec<String>;

/// How many `use` items one name may follow: rustc refuses a cycle, and a chain stays short.
const DEPTH: usize = 16;

/// What one module's scope holds.
#[derive(Default)]
struct Scope {
    /// Each `use` and `extern crate`: the name it gives and the path as written.
    uses: Vec<(String, Vec<String>)>,
    /// Each glob's path as written.
    globs: Vec<Vec<String>>,
    /// The types, functions, constants and statics it declares.
    items: Vec<String>,
}

/// A type I27 judges, in a shipped crate.
struct Judged {
    module: Global,
    name: String,
    file: String,
    line: usize,
    derives: Vec<Vec<String>>,
}

/// One `impl Trait for Type`, with both paths as written.
struct Implemented {
    module: Global,
    ty: Vec<String>,
    implemented: Vec<String>,
}

/// A struct expression whose `field` holds a string literal, with its path as written: a hit of
/// I28 when the path names a statement or one of its variants.
struct Built {
    module: Global,
    path: Vec<String>,
    file: String,
    line: usize,
    field: String,
}

/// The shipped crates' scopes, types, `impl`s and struct expressions.
#[derive(Default)]
pub(super) struct Names {
    scopes: FxHashMap<Global, Scope>,
    types: Vec<Judged>,
    impls: Vec<Implemented>,
    built: Vec<Built>,
}

/// The module of a source under `<crate>/src/`, or of another source's path.
pub(super) fn module_of(file: &str) -> Global {
    let parts: Vec<&str> = file.split('/').collect();
    let (krate, inner) = parts
        .iter()
        .position(|part| *part == "src")
        .and_then(|src| {
            let krate = parts.get(src.checked_sub(1)?)?;
            Some((*krate, parts.get(src + 1..)?))
        })
        .unwrap_or(("", parts.as_slice()));
    let mut module = vec![krate.replace('-', "_")];
    if let Some((last, directories)) = inner.split_last() {
        module.extend(directories.iter().map(|part| (*part).to_owned()));
        let stem = last.trim_end_matches(".rs");
        if !matches!(stem, "lib" | "main" | "mod") {
            module.push(stem.to_owned());
        }
    }
    module
}

impl Names {
    /// A module the scan entered.
    pub(super) fn enter(&mut self, module: &[String]) {
        if !self.scopes.contains_key(module) {
            drop(self.scopes.insert(module.to_vec(), Scope::default()));
        }
    }

    fn scope(&mut self, module: &[String]) -> &mut Scope {
        self.scopes.entry(module.to_vec()).or_default()
    }

    /// A `use` tree in `module`, under the path `prefix` written before it.
    pub(super) fn add_use(
        &mut self,
        module: &[String],
        tree: &syn::UseTree,
        prefix: &mut Vec<String>,
    ) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(super::plain(&path.ident));
                self.add_use(module, &path.tree, prefix);
                drop(prefix.pop());
            }
            syn::UseTree::Name(name) => {
                let given = super::plain(&name.ident);
                self.add_named(module, given.clone(), &given, prefix);
            }
            syn::UseTree::Rename(rename) => {
                let given = super::plain(&rename.rename);
                self.add_named(module, given, &super::plain(&rename.ident), prefix);
            }
            syn::UseTree::Glob(_) => self.scope(module).globs.push(prefix.clone()),
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.add_use(module, item, prefix);
                }
            }
        }
    }

    /// A `use` of `last` under `prefix`, giving `given`; `self` names the prefix.
    fn add_named(&mut self, module: &[String], given: String, last: &str, prefix: &[String]) {
        let mut target = prefix.to_vec();
        let given = if last == "self" {
            prefix
                .last()
                .filter(|_| given == "self")
                .cloned()
                .unwrap_or(given)
        } else {
            target.push(last.to_owned());
            given
        };
        self.scope(module).uses.push((given, target));
    }

    /// `extern crate name as given;`.
    pub(super) fn add_extern(&mut self, module: &[String], given: String, name: String) {
        self.scope(module).uses.push((given, vec![name]));
    }

    /// An item I27 does not judge: a function, a constant, a static, a union, or an unshipped
    /// crate's struct or enum.
    pub(super) fn add_item(&mut self, module: &[String], name: String) {
        self.scope(module).items.push(name);
    }

    /// `type given = target;`.
    pub(super) fn add_alias(&mut self, module: &[String], given: String, target: Vec<String>) {
        self.scope(module).uses.push((given, target));
    }

    /// A shipped crate's struct or enum, with the paths it derives.
    pub(super) fn add_type(
        &mut self,
        module: &[String],
        name: String,
        at: (&str, usize),
        derives: Vec<Vec<String>>,
    ) {
        self.scope(module).items.push(name.clone());
        let (file, line) = at;
        self.types.push(Judged {
            module: module.to_vec(),
            name,
            file: file.to_owned(),
            line,
            derives,
        });
    }

    /// An `impl`.
    pub(super) fn add_impl(
        &mut self,
        module: &[String],
        ty: Vec<String>,
        implemented: Vec<String>,
    ) {
        self.impls.push(Implemented {
            module: module.to_vec(),
            ty,
            implemented,
        });
    }

    /// A struct expression of a shipped source whose `field` holds a string literal.
    pub(super) fn add_built(
        &mut self,
        module: &[String],
        path: Vec<String>,
        at: (&str, usize),
        field: String,
    ) {
        let (file, line) = at;
        self.built.push(Built {
            module: module.to_vec(),
            path,
            file: file.to_owned(),
            line,
            field,
        });
    }

    /// The paths `written`, read in `module`, can name.
    pub(super) fn paths(&self, module: &[String], written: &[String]) -> Vec<Global> {
        self.resolve(module, written, DEPTH)
    }

    /// Whether `path` names a module of this table.
    pub(super) fn holds_module(&self, path: &[String]) -> bool {
        self.scopes.contains_key(path)
    }

    /// The paths `written`, read in `module`, can name, from a crate's name.
    fn resolve(&self, module: &[String], written: &[String], depth: usize) -> Vec<Global> {
        let Some(depth) = depth.checked_sub(1) else {
            return Vec::new();
        };
        let Some((first, rest)) = written.split_first() else {
            return vec![module.to_vec()];
        };
        match first.as_str() {
            "crate" => self.resolve(module.get(..1).unwrap_or_default(), rest, depth),
            "self" => self.resolve(module, rest, depth),
            "super" => {
                let parent = module.split_last().map_or(&[][..], |(_, parent)| parent);
                self.resolve(parent, rest, depth)
            }
            _ => self.in_scope(module, first, rest, depth),
        }
    }

    /// The paths a name in `module` and the segments after it can name: a `use`, else an item or
    /// a child module, else a glob's, else a crate of this table or outside it.
    fn in_scope(
        &self,
        module: &[String],
        first: &str,
        rest: &[String],
        depth: usize,
    ) -> Vec<Global> {
        let scope = self.scopes.get(module);
        let mut found: Vec<Global> = scope
            .into_iter()
            .flat_map(|scope| &scope.uses)
            .filter(|(given, _)| given == first)
            .flat_map(|(_, target)| {
                let whole: Vec<String> = target.iter().chain(rest).cloned().collect();
                self.resolve(module, &whole, depth)
            })
            .collect();
        if !found.is_empty() {
            return found;
        }
        let mut child = module.to_vec();
        child.push(first.to_owned());
        if self.scopes.contains_key(&child) {
            return self.resolve(&child, rest, depth);
        }
        if scope.is_some_and(|scope| scope.items.iter().any(|item| item == first)) {
            child.extend_from_slice(rest);
            return vec![child];
        }
        for glob in scope.into_iter().flat_map(|scope| &scope.globs) {
            found.extend(self.through_glob(module, glob, first, rest, depth));
        }
        if !found.is_empty() {
            return found;
        }
        let root = vec![first.to_owned()];
        if self.scopes.contains_key(&root) {
            return self.resolve(&root, rest, depth);
        }
        let mut outside = root;
        outside.extend_from_slice(rest);
        vec![outside]
    }

    /// What a glob of `module` gives a name: a module of this table when it holds the name, any
    /// name from a path outside the table.
    fn through_glob(
        &self,
        module: &[String],
        glob: &[String],
        first: &str,
        rest: &[String],
        depth: usize,
    ) -> Vec<Global> {
        let mut found = Vec::new();
        for target in self.resolve(module, glob, depth) {
            match self.scopes.get(&target) {
                Some(scope) if !scope.holds(first) => {}
                Some(_) => {
                    let mut whole = vec![first.to_owned()];
                    whole.extend_from_slice(rest);
                    found.extend(self.resolve(&target, &whole, depth));
                }
                None => {
                    let mut whole = target;
                    whole.push(first.to_owned());
                    whole.extend_from_slice(rest);
                    found.push(whole);
                }
            }
        }
        found
    }

    fn implements(&self, ty: &Judged, implemented: &str) -> bool {
        let mut own = ty.module.clone();
        own.push(ty.name.clone());
        self.impls.iter().any(|item| {
            ends_in(
                self.resolve(&item.module, &item.implemented, DEPTH),
                implemented,
            ) && self.resolve(&item.module, &item.ty, DEPTH).contains(&own)
        })
    }

    fn derives(&self, ty: &Judged, wanted: impl Fn(&[String]) -> bool) -> bool {
        ty.derives.iter().any(|path| {
            self.resolve(&ty.module, path, DEPTH)
                .iter()
                .any(|path| wanted(path))
        })
    }

    /// Whether `ty` derives siros-i18n's `Message`.
    fn statement(&self, ty: &Judged) -> bool {
        self.derives(ty, |path| path.last().is_some_and(|last| last == "Message"))
    }

    /// The hits of I27 and I28.
    pub(super) fn judge(&self, hits: &mut Vec<Hit>) {
        for ty in &self.types {
            let thiserror = self.derives(
                ty,
                |path| matches!(path, [first, last] if first == "thiserror" && last == "Error"),
            );
            let explain =
                self.derives(ty, |path| path.last().is_some_and(|last| last == "Explain"));
            let rule = if thiserror && !explain && !self.implements(ty, "Explain") {
                format!("I27: the error `{}` does not implement `Explain`", ty.name)
            } else if self.statement(ty) && self.implements(ty, "Display") {
                format!("I27: the statement `{}` implements `Display`", ty.name)
            } else {
                continue;
            };
            hits.push(Hit {
                file: ty.file.clone(),
                line: ty.line,
                rule,
            });
        }
        for built in &self.built {
            let named = self.resolve(&built.module, &built.path, DEPTH);
            let statement = self
                .types
                .iter()
                .find(|ty| self.statement(ty) && names_type(&named, ty));
            if let Some(ty) = statement {
                hits.push(Hit {
                    file: built.file.clone(),
                    line: built.line,
                    rule: format!(
                        "I28: the statement `{}`'s field `{}` holds a literal",
                        ty.name, built.field
                    ),
                });
            }
        }
    }
}

/// Whether one of `paths` names `ty` or one of its variants.
fn names_type(paths: &[Global], ty: &Judged) -> bool {
    paths.iter().any(|path| {
        let named = |at: &[String]| {
            at.split_last()
                .is_some_and(|(name, module)| *name == ty.name && module == ty.module.as_slice())
        };
        named(path) || path.split_last().is_some_and(|(_, ty_path)| named(ty_path))
    })
}

impl Scope {
    fn holds(&self, name: &str) -> bool {
        self.items.iter().any(|item| item == name)
            || self.uses.iter().any(|(given, _)| given == name)
            || !self.globs.is_empty()
    }
}

fn ends_in(paths: Vec<Global>, last: &str) -> bool {
    paths
        .iter()
        .any(|path| path.last().is_some_and(|it| it == last))
}
