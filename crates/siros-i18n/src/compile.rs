//! A message's compilation into its render form: its variables resolved against its key's
//! declaration, each expression's function found among the registered format modules, and each
//! call compiled by its module with the module's options for the locale.

use siros_explain::{ArgKind, Entry, Keyed};

use crate::error::{ModuleError, Refusal, Validity};
use crate::form::{
    BodyForm, CompiledCall, Dir, Expression, KeyRef, MessageForm, ParamForm, PartForm, Root,
    SelectorForm, VariantForm,
};
use crate::format::{Call, Compilers, FormatCompiler, FormatId, Operand, ParsedFormats, Uses};
use crate::mf2::ast::{self, Body, Declaration, Function, Key, MarkupKind, Part};
use crate::module::Declared;
use crate::sink::Style;

/// Where a message stands: its key, its locale, and its declaration.
pub(crate) struct Site<'a> {
    pub(crate) key: &'a str,
    pub(crate) locale: &'a str,
    pub(crate) message: &'a Declared,
}

impl Site<'_> {
    fn kind(&self, call: &str, refusal: Refusal) -> ModuleError {
        ModuleError::Kind {
            key: self.key.to_owned(),
            locale: self.locale.to_owned(),
            call: call.to_owned(),
            refusal,
        }
    }

    fn markup(&self, markup: &str, make: fn(String, String, String) -> ModuleError) -> ModuleError {
        make(
            self.key.to_owned(),
            self.locale.to_owned(),
            markup.to_owned(),
        )
    }
}

/// The function a placeholder of an argument's kind calls when the placeholder names none:
/// numbers through `:number`, amounts and currencies through `:currency`, dates, times and lists
/// through the locale's formats, texts as strings.
pub(crate) const fn implicit(kind: ArgKind) -> &'static str {
    match kind {
        ArgKind::Count | ArgKind::Decimal => "number",
        ArgKind::Amount | ArgKind::Currency => "currency",
        ArgKind::Date => "siros:date",
        ArgKind::Time => "siros:time",
        ArgKind::DateTime => "siros:datetime",
        ArgKind::List => "siros:list",
        ArgKind::Message | ArgKind::Name | ArgKind::Text | ArgKind::Raw => "string",
    }
}

/// An expression before its call is compiled.
struct Spec {
    compiler: &'static dyn FormatCompiler,
    function: &'static str,
    origin: Origin,
    previous: Option<usize>,
    options: Vec<Entry<String, String>>,
    /// The call as written, [`ModuleError::Kind`]'s.
    call: String,
    dir: Dir,
    format: bool,
    select: bool,
}

/// What a variable stands for.
#[derive(Clone)]
enum Binding {
    Argument(Argument),
    Literal(String),
    Expression(usize),
}

/// A parameter of the key's declaration: its index and its kind.
#[derive(Debug, Clone, Copy)]
struct Argument {
    index: usize,
    kind: ArgKind,
}

/// What an expression's chain of calls starts from.
#[derive(Clone)]
enum Origin {
    None,
    Literal(String),
    Argument(Argument),
}

impl Origin {
    fn root(&self) -> Root {
        match self {
            Self::None => Root::None,
            Self::Literal(literal) => Root::Literal(literal.clone()),
            Self::Argument(argument) => Root::Argument(argument.index),
        }
    }
}

/// A variable a declaration bound.
struct Bound {
    name: String,
    binding: Binding,
}

/// The resolution in progress: the expressions so far and the variables declared.
struct Resolver<'a> {
    site: Site<'a>,
    specs: Vec<Spec>,
    bound: Vec<Bound>,
}

/// A message resolved: its expressions and its body, ready for its calls to compile.
pub(crate) struct Resolved<'a> {
    resolver: Resolver<'a>,
    body: BodyForm,
}

/// Resolves a parsed message: refused for an undeclared argument, a function no registered format
/// module provides, a bad `u:` option or a variable option value, and markup outside the styles.
pub(crate) fn resolve<'a>(
    site: Site<'a>,
    message: &ast::Message,
    compilers: &Compilers,
) -> Result<Resolved<'a>, ModuleError> {
    let mut resolver = Resolver {
        site,
        specs: Vec::new(),
        bound: Vec::new(),
    };
    for declaration in &message.declarations {
        let (name, binding) = match declaration {
            Declaration::Input { name, function } => {
                let argument = resolver.argument(name)?;
                let binding = match function {
                    Some(function) => {
                        let operand = ast::Operand::Variable(name.clone());
                        Binding::Expression(resolver.call(function, Some(&operand), compilers)?)
                    }
                    None => Binding::Argument(argument),
                };
                (name, binding)
            }
            Declaration::Local { name, expression } => {
                (name, resolver.bind(expression, compilers)?)
            }
        };
        resolver.bound.push(Bound {
            name: name.clone(),
            binding,
        });
    }
    let body = match &message.body {
        Body::Pattern(pattern) => BodyForm::Pattern(resolver.pattern(pattern, compilers)?),
        Body::Matcher {
            selectors,
            variants,
        } => resolver.matcher(selectors, variants, compilers)?,
    };
    Ok(Resolved { resolver, body })
}

impl Resolved<'_> {
    /// The format modules the message's calls use.
    pub(crate) fn compilers(&self) -> impl Iterator<Item = &'static dyn FormatCompiler> + '_ {
        self.resolver.specs.iter().map(|spec| spec.compiler)
    }

    /// The message compiled, each call by its module's parsed options for the locale.
    pub(crate) fn compile<'p>(
        self,
        parsed: &dyn Fn(FormatId) -> Option<&'p dyn ParsedFormats>,
    ) -> Result<MessageForm, ModuleError> {
        let resolver = &self.resolver;
        let keyed = resolver
            .specs
            .iter()
            .map(|spec| {
                let entries = spec
                    .options
                    .iter()
                    .map(|entry| Entry::new(entry.key().as_str(), entry.value().as_str()));
                Keyed::new(entries.collect()).map_err(|repeated| {
                    resolver.invalid(Validity::DuplicateOptionName {
                        option: repeated.0.to_owned(),
                    })
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut expressions = Vec::with_capacity(resolver.specs.len());
        for (index, spec) in resolver.specs.iter().enumerate() {
            let format = spec.compiler.id();
            let parsed = parsed(format).ok_or_else(|| ModuleError::Function {
                key: resolver.site.key.to_owned(),
                locale: resolver.site.locale.to_owned(),
                function: spec.function.to_owned(),
            })?;
            let bytes = resolver
                .with_call(index, &keyed, &mut |call| parsed.compile(call))
                .map_err(|refusal| resolver.site.kind(&spec.call, refusal))?;
            expressions.push(Expression {
                root: spec.origin.root(),
                call: CompiledCall {
                    format: format.as_str().to_owned(),
                    bytes,
                },
                dir: spec.dir,
            });
        }
        Ok(MessageForm {
            id: resolver.site.message.id.clone(),
            params: resolver.site.message.params.clone(),
            expressions,
            body: self.body,
        })
    }
}

impl Resolver<'_> {
    /// Calls `compile` with expression `index`'s call, its earlier calls chained under it.
    fn with_call(
        &self,
        index: usize,
        keyed: &[Keyed<&str, &str>],
        compile: &mut dyn FnMut(&Call<'_>) -> Result<Vec<u8>, Refusal>,
    ) -> Result<Vec<u8>, Refusal> {
        let (Some(spec), Some(options)) = (self.specs.get(index), keyed.get(index)) else {
            return Err(Refusal::Operand);
        };
        let uses = Uses::new(spec.format, spec.select);
        match spec.previous {
            Some(previous) => self.with_call(previous, keyed, &mut |earlier| {
                compile(&Call::new(
                    spec.function,
                    Operand::Call(earlier),
                    options,
                    uses,
                ))
            }),
            None => {
                let operand = match &spec.origin {
                    Origin::None => Operand::None,
                    Origin::Literal(literal) => Operand::Literal(literal),
                    Origin::Argument(argument) => Operand::Argument(argument.kind),
                };
                compile(&Call::new(spec.function, operand, options, uses))
            }
        }
    }

    fn params(&self) -> &[ParamForm] {
        &self.site.message.params
    }

    fn invalid(&self, rule: Validity) -> ModuleError {
        ModuleError::Invalid {
            key: self.site.key.to_owned(),
            locale: self.site.locale.to_owned(),
            rule,
        }
    }

    /// The parameter named `name`.
    fn argument(&self, name: &str) -> Result<Argument, ModuleError> {
        let found = self
            .params()
            .iter()
            .enumerate()
            .find(|(_, param)| param.name == name);
        found
            .map(|(index, param)| Argument {
                index,
                kind: param.kind,
            })
            .ok_or_else(|| ModuleError::Argument {
                key: self.site.key.to_owned(),
                locale: self.site.locale.to_owned(),
                argument: name.to_owned(),
            })
    }

    /// What `name` stands for: the latest declaration of it, else the parameter.
    fn lookup(&self, name: &str) -> Result<Binding, ModuleError> {
        match self.bound.iter().rev().find(|bound| bound.name == name) {
            Some(bound) => Ok(bound.binding.clone()),
            None => self.argument(name).map(Binding::Argument),
        }
    }

    /// Marks an expression's value as formatted, or as selected on.
    fn mark(&mut self, index: usize, format: bool) {
        if let Some(spec) = self.specs.get_mut(index) {
            if format {
                spec.format = true;
            } else {
                spec.select = true;
            }
        }
    }

    /// What a local declaration's expression binds.
    fn bind(
        &mut self,
        expression: &ast::Expression,
        compilers: &Compilers,
    ) -> Result<Binding, ModuleError> {
        match expression {
            ast::Expression::Operand {
                operand: ast::Operand::Literal(literal),
                function: None,
            } => Ok(Binding::Literal(literal.clone())),
            ast::Expression::Operand {
                operand: ast::Operand::Variable(name),
                function: None,
            } => self.lookup(name),
            ast::Expression::Operand {
                operand,
                function: Some(function),
            } => self
                .call(function, Some(operand), compilers)
                .map(Binding::Expression),
            ast::Expression::Function(function) => self
                .call(function, None, compilers)
                .map(Binding::Expression),
        }
    }

    /// The expression a placeholder formats.
    fn placeholder(
        &mut self,
        expression: &ast::Expression,
        compilers: &Compilers,
    ) -> Result<usize, ModuleError> {
        let index = match expression {
            ast::Expression::Operand {
                operand,
                function: None,
            } => {
                let (origin, operand, function) = match operand {
                    ast::Operand::Literal(literal) => (
                        Origin::Literal(literal.clone()),
                        format!("|{literal}|"),
                        "string",
                    ),
                    ast::Operand::Variable(name) => match self.lookup(name)? {
                        Binding::Expression(index) => {
                            self.mark(index, true);
                            return Ok(index);
                        }
                        Binding::Literal(literal) => {
                            (Origin::Literal(literal), format!("${name}"), "string")
                        }
                        Binding::Argument(argument) => (
                            Origin::Argument(argument),
                            format!("${name}"),
                            implicit(argument.kind),
                        ),
                    },
                };
                let (compiler, function) = self.provider(compilers, function)?;
                self.specs.push(Spec {
                    compiler,
                    function,
                    origin,
                    previous: None,
                    options: Vec::new(),
                    call: format!("{operand} :{function}"),
                    dir: Dir::Inherit,
                    format: false,
                    select: false,
                });
                self.specs.len() - 1
            }
            ast::Expression::Operand {
                operand,
                function: Some(function),
            } => self.call(function, Some(operand), compilers)?,
            ast::Expression::Function(function) => self.call(function, None, compilers)?,
        };
        self.mark(index, true);
        Ok(index)
    }

    fn provider(
        &self,
        compilers: &Compilers,
        function: &str,
    ) -> Result<(&'static dyn FormatCompiler, &'static str), ModuleError> {
        compilers
            .provider(function)
            .ok_or_else(|| ModuleError::Function {
                key: self.site.key.to_owned(),
                locale: self.site.locale.to_owned(),
                function: function.to_owned(),
            })
    }

    /// A call of `function` on `operand`.
    fn call(
        &mut self,
        function: &Function,
        operand: Option<&ast::Operand>,
        compilers: &Compilers,
    ) -> Result<usize, ModuleError> {
        let (compiler, name) = self.provider(compilers, &function.name)?;
        let (origin, previous, mut dir, written) = match operand {
            None => (Origin::None, None, Dir::Inherit, format!(":{name}")),
            Some(ast::Operand::Literal(literal)) => (
                Origin::Literal(literal.clone()),
                None,
                Dir::Inherit,
                format!("|{literal}| :{name}"),
            ),
            Some(ast::Operand::Variable(variable)) => {
                let written = format!("${variable} :{name}");
                match self.lookup(variable)? {
                    Binding::Argument(argument) => {
                        (Origin::Argument(argument), None, Dir::Inherit, written)
                    }
                    Binding::Literal(literal) => {
                        (Origin::Literal(literal), None, Dir::Inherit, written)
                    }
                    Binding::Expression(index) => {
                        let Some(earlier) = self.specs.get(index) else {
                            return Err(self.invalid(Validity::MissingSelectorAnnotation {
                                variable: variable.clone(),
                            }));
                        };
                        (earlier.origin.clone(), Some(index), earlier.dir, written)
                    }
                }
            }
        };
        let mut options = Vec::new();
        for option in &function.options {
            let refuse = || {
                self.site.kind(
                    &written,
                    Refusal::Option {
                        option: option.name.clone(),
                    },
                )
            };
            let ast::Operand::Literal(value) = &option.value else {
                return Err(refuse());
            };
            match option.name.as_str() {
                "u:dir" => {
                    dir = match value.as_str() {
                        "ltr" => Dir::Ltr,
                        "rtl" => Dir::Rtl,
                        "auto" => Dir::Auto,
                        "inherit" => Dir::Inherit,
                        _ => return Err(refuse()),
                    };
                }
                "u:id" => {}
                other if other.starts_with("u:") => return Err(refuse()),
                other => options.push(Entry::new(other.to_owned(), value.clone())),
            }
        }
        self.specs.push(Spec {
            compiler,
            function: name,
            origin,
            previous,
            options,
            call: written,
            dir,
            format: false,
            select: false,
        });
        Ok(self.specs.len() - 1)
    }

    /// A `.match` body: each selector's expression and distinct keys, and each variant's keys
    /// as indices into them.
    fn matcher(
        &mut self,
        selectors: &[String],
        variants: &[ast::Variant],
        compilers: &Compilers,
    ) -> Result<BodyForm, ModuleError> {
        let mut forms = Vec::with_capacity(selectors.len());
        for (column, selector) in selectors.iter().enumerate() {
            let Binding::Expression(expression) = self.lookup(selector)? else {
                return Err(self.invalid(Validity::MissingSelectorAnnotation {
                    variable: selector.clone(),
                }));
            };
            self.mark(expression, false);
            let mut keys: Vec<String> = Vec::new();
            for variant in variants {
                if let Some(Key::Literal(key)) = variant.keys.get(column)
                    && !keys.contains(key)
                {
                    keys.push(key.clone());
                }
            }
            forms.push(SelectorForm { expression, keys });
        }
        let mut compiled = Vec::with_capacity(variants.len());
        for variant in variants {
            let mut keys = Vec::with_capacity(forms.len());
            for (key, selector) in variant.keys.iter().zip(&forms) {
                keys.push(match key {
                    Key::CatchAll => KeyRef::CatchAll,
                    Key::Literal(key) => match selector.keys.iter().position(|k| k == key) {
                        Some(index) => KeyRef::Key(index),
                        None => return Err(self.invalid(Validity::VariantKeyMismatch)),
                    },
                });
            }
            compiled.push(VariantForm {
                keys,
                pattern: self.pattern(&variant.pattern, compilers)?,
            });
        }
        Ok(BodyForm::Select {
            selectors: forms,
            variants: compiled,
        })
    }

    /// A pattern, its markup checked to open and close each style in nested order, once.
    fn pattern(
        &mut self,
        pattern: &ast::Pattern,
        compilers: &Compilers,
    ) -> Result<Vec<PartForm>, ModuleError> {
        let mut parts = Vec::with_capacity(pattern.len());
        let mut open: Vec<(Style, &str)> = Vec::new();
        for part in pattern {
            parts.push(match part {
                Part::Text(text) => PartForm::Text(text.clone()),
                Part::Expression(expression) => {
                    PartForm::Expression(self.placeholder(expression, compilers)?)
                }
                Part::Markup(markup) => {
                    let name = markup.name.as_str();
                    let style =
                        Style::named(name).ok_or_else(|| self.site.markup(name, markup_error))?;
                    if !markup.options.is_empty() {
                        return Err(self.site.markup(name, markup_option));
                    }
                    match markup.kind {
                        MarkupKind::Open if open.iter().all(|(earlier, _)| *earlier != style) => {
                            open.push((style, name));
                            PartForm::Open(style)
                        }
                        MarkupKind::Close => match open.pop() {
                            Some((last, _)) if last == style => PartForm::Close(style),
                            Some(_) | None => return Err(self.site.markup(name, nesting)),
                        },
                        MarkupKind::Open | MarkupKind::Standalone => {
                            return Err(self.site.markup(name, nesting));
                        }
                    }
                }
            });
        }
        match open.last() {
            Some((_, name)) => Err(self.site.markup(name, nesting)),
            None => Ok(parts),
        }
    }
}

const fn markup_error(key: String, locale: String, markup: String) -> ModuleError {
    ModuleError::Markup {
        key,
        locale,
        markup,
    }
}

const fn markup_option(key: String, locale: String, markup: String) -> ModuleError {
    ModuleError::MarkupOption {
        key,
        locale,
        markup,
    }
}

const fn nesting(key: String, locale: String, markup: String) -> ModuleError {
    ModuleError::Nesting {
        key,
        locale,
        markup,
    }
}
