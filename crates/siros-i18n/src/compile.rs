//! A message compiled for a context, and resolved. Its declarations bind variables by name: an
//! argument, a literal, or an expression's call chain, which a later expression on the variable
//! extends. Each placeholder and each selector compiles the chain it reads with the function that
//! formats or selects there; a declaration no placeholder or selector reads never runs. Markup
//! opens and closes the styles in nested order.
//!
//! A message resolves lazily: a placeholder formats when the pattern writes it, and a selector
//! selects when the matcher picks a variant (spec/formatting.md "Pattern Selection").

use crate::context::Bidi;
use crate::error::{LoadError, Refusal, ResolveError, SyntaxRule};
use crate::format::{
    Argument, CallSpec, Chain, Direction, Failure, Formats, Formatter, Function, OptionValue,
    Refused, Root, Selector,
};
use crate::mf2::ast::{self, Key, MarkupKind};
use crate::text::{Style, Text, Writer};

/// An expression's `u:dir`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    Ltr,
    Rtl,
    Auto,
    Inherit,
}

/// A message, compiled: its module's direction and its body.
#[derive(Debug, Clone)]
pub(crate) struct Compiled {
    direction: Direction,
    body: Body,
}

/// A message's body.
#[derive(Debug, Clone)]
enum Body {
    Pattern(Pattern),
    /// `.match`: its selectors, its variants with a key, and the variant whose keys are all `*`.
    Select {
        columns: Vec<Column>,
        variants: Vec<Variant>,
        fallback: Pattern,
    },
}

/// A selector, and the distinct keys of its column.
#[derive(Debug, Clone)]
struct Column {
    selector: Selector,
    called: Called,
    keys: Vec<String>,
}

/// A variant with a key: one key per selector, and its pattern.
#[derive(Debug, Clone)]
struct Variant {
    keys: Vec<Key>,
    pattern: Pattern,
}

type Pattern = Vec<Part>;

/// A part of a compiled pattern.
#[derive(Debug, Clone)]
enum Part {
    Text(String),
    Placeholder(Placeholder),
    Open(Style),
    Close(Style),
}

/// A placeholder: its compiled call, its `u:dir`, and the functions its errors name.
#[derive(Debug, Clone)]
struct Placeholder {
    formatter: Formatter,
    called: Called,
    dir: Dir,
}

/// What a chain's errors and the context's check read of it: the innermost function, whose
/// operand is the text, the outermost, which formats or selects, and the arguments it reads.
#[derive(Debug, Clone)]
struct Called {
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "date",
        feature = "check"
    ))]
    innermost: Function,
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "date"
    ))]
    outermost: Function,
    #[cfg(feature = "check")]
    reads: Vec<String>,
}

impl Called {
    fn of(
        #[cfg_attr(
            not(any(
                feature = "number",
                feature = "currency",
                feature = "offset",
                feature = "date",
                feature = "check"
            )),
            expect(unused_variables, reason = "a build of `:string` alone reads no call")
        )]
        chain: &Chain,
    ) -> Self {
        Self {
            #[cfg(any(
                feature = "number",
                feature = "currency",
                feature = "offset",
                feature = "date",
                feature = "check"
            ))]
            innermost: chain
                .inner
                .first()
                .map_or(chain.outer.function, |call| call.function),
            #[cfg(any(
                feature = "number",
                feature = "currency",
                feature = "offset",
                feature = "date"
            ))]
            outermost: chain.outer.function,
            #[cfg(feature = "check")]
            reads: chain.reads(),
        }
    }

    /// The resolution error of `failure` in the message `id`.
    fn error(&self, id: &str, failure: Failure) -> ResolveError {
        match failure {
            #[cfg(any(
                feature = "number",
                feature = "currency",
                feature = "offset",
                feature = "date",
                feature = "check"
            ))]
            Failure::Operand => ResolveError::Operand {
                id: id.to_owned(),
                function: self.innermost.name().to_owned(),
            },
            #[cfg(any(
                feature = "number",
                feature = "currency",
                feature = "offset",
                feature = "date"
            ))]
            Failure::Option(option) => ResolveError::Option {
                id: id.to_owned(),
                function: self.outermost.name().to_owned(),
                option,
            },
            Failure::Unresolved(key) => ResolveError::Unresolved {
                id: id.to_owned(),
                key,
            },
        }
    }
}

/// What a variable stands for.
#[derive(Debug, Clone)]
enum Binding {
    /// The argument of this key.
    Argument(String),
    /// A literal.
    Literal(String),
    /// An expression with a function.
    Expression(Expression),
}

/// An expression with a function: its call chain and its `u:dir`.
#[derive(Debug, Clone)]
struct Expression {
    chain: Chain,
    dir: Dir,
}

/// A `:string` call on `root`: an expression without a function.
fn string(root: Root) -> Expression {
    Expression {
        chain: Chain {
            root,
            inner: Vec::new(),
            outer: CallSpec {
                function: Function::String,
                options: Vec::new(),
            },
        },
        dir: Dir::Inherit,
    }
}

/// The compilation of one message: its id, its line, the context's formats, and the variables
/// its declarations bound so far.
struct Compiler<'c> {
    id: &'c str,
    line: usize,
    formats: &'c Formats,
    bound: Vec<(String, Binding)>,
}

/// Compiles the message `id`, which starts at `line` of a module whose direction is
/// `direction`.
///
/// # Errors
///
/// [`LoadError`] for a function the build lacks, a function whose section no module defined, a
/// call its function refuses, and markup outside the styles or not nested.
pub(crate) fn compile(
    id: &str,
    line: usize,
    message: &ast::Message,
    direction: Direction,
    formats: &Formats,
) -> Result<Compiled, LoadError> {
    let mut compiler = Compiler {
        id,
        line,
        formats,
        bound: Vec::new(),
    };
    for declaration in &message.declarations {
        let (name, binding) = match declaration {
            ast::Declaration::Input {
                name,
                function: Some(function),
            } => {
                let operand = ast::Operand::Variable(name.clone());
                let expression = compiler.call(Some(&operand), function)?;
                (name, Binding::Expression(expression))
            }
            ast::Declaration::Input {
                name,
                function: None,
            } => (name, Binding::Argument(name.clone())),
            ast::Declaration::Local { name, expression } => (name, compiler.bind(expression)?),
        };
        compiler.bound.push((name.clone(), binding));
    }
    let body = match &message.body {
        ast::Body::Pattern(pattern) => Body::Pattern(compiler.pattern(pattern)?),
        ast::Body::Matcher {
            selectors,
            variants,
        } => compiler.matcher(selectors, variants)?,
    };
    Ok(Compiled { direction, body })
}

impl Compiler<'_> {
    fn syntax(&self, rule: SyntaxRule) -> LoadError {
        LoadError::Syntax {
            line: self.line,
            rule,
        }
    }

    /// The refusal of a chain whose outermost function is `function`.
    fn refused(&self, function: Function, refused: Refused) -> LoadError {
        let (id, function) = (self.id.to_owned(), function.name().to_owned());
        match refused {
            #[cfg(any(
                feature = "number",
                feature = "currency",
                feature = "offset",
                feature = "date"
            ))]
            Refused::Undefined => LoadError::Option { id, function },
            Refused::Call(refusal) => LoadError::Call {
                id,
                function,
                refusal,
            },
        }
    }

    /// What `name` stands for: its declaration, else the argument of its name.
    fn lookup(&self, name: &str) -> Binding {
        self.bound
            .iter()
            .rev()
            .find(|(bound, _)| bound == name)
            .map_or_else(|| Binding::Argument(name.to_owned()), |(_, b)| b.clone())
    }

    /// What a local declaration's expression binds.
    fn bind(&self, expression: &ast::Expression) -> Result<Binding, LoadError> {
        match expression {
            ast::Expression::Operand {
                operand: ast::Operand::Literal(literal),
                function: None,
            } => Ok(Binding::Literal(literal.clone())),
            ast::Expression::Operand {
                operand: ast::Operand::Variable(name),
                function: None,
            } => Ok(self.lookup(name)),
            ast::Expression::Operand {
                operand,
                function: Some(function),
            } => self.call(Some(operand), function).map(Binding::Expression),
            ast::Expression::Function(function) => {
                self.call(None, function).map(Binding::Expression)
            }
        }
    }

    /// The expression a placeholder formats.
    fn expression(&self, expression: &ast::Expression) -> Result<Expression, LoadError> {
        match expression {
            ast::Expression::Operand {
                operand: ast::Operand::Literal(literal),
                function: None,
            } => Ok(string(Root::Literal(literal.clone()))),
            ast::Expression::Operand {
                operand: ast::Operand::Variable(name),
                function: None,
            } => Ok(match self.lookup(name) {
                Binding::Argument(key) => string(Root::Argument(key)),
                Binding::Literal(literal) => string(Root::Literal(literal)),
                Binding::Expression(expression) => expression,
            }),
            ast::Expression::Operand {
                operand,
                function: Some(function),
            } => self.call(Some(operand), function),
            ast::Expression::Function(function) => self.call(None, function),
        }
    }

    /// A call of `function` on `operand`: the operand's chain extended, its `u:` options read,
    /// and each other option's value a literal or an argument.
    fn call(
        &self,
        operand: Option<&ast::Operand>,
        function: &ast::Function,
    ) -> Result<Expression, LoadError> {
        let name = function.name.as_str();
        let called = Function::named(name).ok_or_else(|| LoadError::Function {
            id: self.id.to_owned(),
            function: name.to_owned(),
        })?;
        if !self.formats.defines(called) {
            return Err(LoadError::Option {
                id: self.id.to_owned(),
                function: name.to_owned(),
            });
        }
        let (root, inner, mut dir) = match operand {
            None => (Root::None, Vec::new(), Dir::Inherit),
            Some(ast::Operand::Literal(literal)) => {
                (Root::Literal(literal.clone()), Vec::new(), Dir::Inherit)
            }
            Some(ast::Operand::Variable(variable)) => match self.lookup(variable) {
                Binding::Argument(key) => (Root::Argument(key), Vec::new(), Dir::Inherit),
                Binding::Literal(literal) => (Root::Literal(literal), Vec::new(), Dir::Inherit),
                Binding::Expression(Expression { chain, dir }) => {
                    let mut inner = chain.inner;
                    inner.push(chain.outer);
                    (chain.root, inner, dir)
                }
            },
        };
        let refuse = |option: &str| LoadError::Call {
            id: self.id.to_owned(),
            function: name.to_owned(),
            refusal: Refusal::Option {
                option: option.to_owned(),
            },
        };
        let mut options = Vec::new();
        for option in &function.options {
            let value = match &option.value {
                ast::Operand::Literal(literal) => OptionValue::Literal(literal.clone()),
                ast::Operand::Variable(variable) => match self.lookup(variable) {
                    Binding::Argument(key) => OptionValue::Argument(key),
                    Binding::Literal(literal) => OptionValue::Local(literal),
                    Binding::Expression(_) => return Err(refuse(&option.name)),
                },
            };
            match (option.name.as_str(), value) {
                ("u:dir", OptionValue::Literal(text) | OptionValue::Local(text)) => {
                    dir = match text.as_str() {
                        "ltr" => Dir::Ltr,
                        "rtl" => Dir::Rtl,
                        "auto" => Dir::Auto,
                        "inherit" => Dir::Inherit,
                        _ => return Err(refuse(&option.name)),
                    };
                }
                ("u:id", _) => {}
                (other, _) if other.starts_with("u:") => return Err(refuse(other)),
                (other, value) => options.push((other.to_owned(), value)),
            }
        }
        Ok(Expression {
            chain: Chain {
                root,
                inner,
                outer: CallSpec {
                    function: called,
                    options,
                },
            },
            dir,
        })
    }

    /// A placeholder: its expression compiled to format.
    fn placeholder(&self, expression: &ast::Expression) -> Result<Placeholder, LoadError> {
        let Expression { chain, dir } = self.expression(expression)?;
        let formatter = Formatter::compile(&chain, self.formats)
            .map_err(|refused| self.refused(chain.outer.function, refused))?;
        Ok(Placeholder {
            formatter,
            called: Called::of(&chain),
            dir,
        })
    }

    /// A `.match` body: each selector compiled over its column's keys, each variant's pattern,
    /// and the variant whose keys are all `*`.
    fn matcher(&self, selectors: &[String], variants: &[ast::Variant]) -> Result<Body, LoadError> {
        let mut columns = Vec::with_capacity(selectors.len());
        for (column, name) in selectors.iter().enumerate() {
            let Binding::Expression(Expression { chain, .. }) = self.lookup(name) else {
                return Err(self.syntax(SyntaxRule::MissingSelectorAnnotation {
                    id: self.id.to_owned(),
                    variable: name.clone(),
                }));
            };
            let mut keys: Vec<String> = Vec::new();
            for variant in variants {
                if let Some(Key::Literal(key)) = variant.keys.get(column)
                    && !keys.contains(key)
                {
                    keys.push(key.clone());
                }
            }
            let selector = Selector::compile(&chain, &keys, self.formats)
                .map_err(|refused| self.refused(chain.outer.function, refused))?;
            columns.push(Column {
                selector,
                called: Called::of(&chain),
                keys,
            });
        }
        let mut keyed = Vec::with_capacity(variants.len());
        let mut fallback = None;
        for variant in variants {
            let pattern = self.pattern(&variant.pattern)?;
            if variant.keys.len() != columns.len() {
                return Err(self.syntax(SyntaxRule::VariantKeyMismatch {
                    id: self.id.to_owned(),
                }));
            }
            if variant.keys.iter().all(|key| *key == Key::CatchAll) {
                if fallback.replace(pattern).is_some() {
                    return Err(self.syntax(SyntaxRule::DuplicateVariant {
                        id: self.id.to_owned(),
                    }));
                }
            } else {
                keyed.push(Variant {
                    keys: variant.keys.clone(),
                    pattern,
                });
            }
        }
        let fallback = fallback.ok_or_else(|| {
            self.syntax(SyntaxRule::MissingFallbackVariant {
                id: self.id.to_owned(),
            })
        })?;
        Ok(Body::Select {
            columns,
            variants: keyed,
            fallback,
        })
    }

    /// A pattern, its markup checked to open and close each style in nested order, once.
    fn pattern(&self, pattern: &ast::Pattern) -> Result<Pattern, LoadError> {
        let mut parts = Vec::with_capacity(pattern.len());
        let mut open: Vec<(Style, &str)> = Vec::new();
        for part in pattern {
            parts.push(match part {
                ast::Part::Text(text) => Part::Text(text.clone()),
                ast::Part::Expression(expression) => {
                    Part::Placeholder(self.placeholder(expression)?)
                }
                ast::Part::Markup(markup) => {
                    let name = markup.name.as_str();
                    let refuse = |rule: fn(String, String) -> SyntaxRule| {
                        self.syntax(rule(self.id.to_owned(), name.to_owned()))
                    };
                    let style = Style::named(name).ok_or_else(|| refuse(markup_rule))?;
                    if !markup.options.is_empty() {
                        return Err(refuse(option_rule));
                    }
                    match markup.kind {
                        MarkupKind::Open if open.iter().all(|(earlier, _)| *earlier != style) => {
                            open.push((style, name));
                            Part::Open(style)
                        }
                        MarkupKind::Close => match open.pop() {
                            Some((last, _)) if last == style => Part::Close(style),
                            Some(_) | None => return Err(refuse(nesting_rule)),
                        },
                        MarkupKind::Open | MarkupKind::Standalone => {
                            return Err(refuse(nesting_rule));
                        }
                    }
                }
            });
        }
        match open.last() {
            Some((_, name)) => {
                Err(self.syntax(nesting_rule(self.id.to_owned(), (*name).to_owned())))
            }
            None => Ok(parts),
        }
    }
}

const fn markup_rule(id: String, markup: String) -> SyntaxRule {
    SyntaxRule::Markup { id, markup }
}

const fn option_rule(id: String, markup: String) -> SyntaxRule {
    SyntaxRule::MarkupOption { id, markup }
}

const fn nesting_rule(id: String, markup: String) -> SyntaxRule {
    SyntaxRule::Nesting { id, markup }
}

/// The isolating character a placeholder opens under MF2's Default Bidi Strategy; `None` for a
/// placeholder it does not isolate. `dir` is its `u:dir`, `value` its formatted value's direction
/// and `message` the message's.
fn isolation(bidi: Bidi, dir: Dir, value: Direction, message: Direction) -> Option<&'static str> {
    if bidi == Bidi::None {
        return None;
    }
    let direction = match dir {
        Dir::Ltr => Direction::Ltr,
        Dir::Rtl => Direction::Rtl,
        Dir::Auto => Direction::Unknown,
        Dir::Inherit => value,
    };
    match direction {
        Direction::Ltr if message == Direction::Ltr && dir == Dir::Inherit => None,
        Direction::Ltr => Some("\u{2066}"),
        Direction::Rtl => Some("\u{2067}"),
        Direction::Unknown => Some("\u{2068}"),
    }
}

/// Each selector's matching keys, best first.
struct Ranks<'k>(Vec<Vec<&'k str>>);

/// The rank of `key` among a selector's matching keys: `Some(None)` for `*`, which matches last,
/// and `None` for a key that does not match.
fn rank(matched: &[&str], key: &Key) -> Option<Option<usize>> {
    match key {
        Key::CatchAll => Some(None),
        Key::Literal(key) => matched.iter().position(|m| *m == key).map(Some),
    }
}

impl Ranks<'_> {
    /// Whether every key of `variant` matches.
    fn matches(&self, variant: &Variant) -> bool {
        variant
            .keys
            .iter()
            .zip(&self.0)
            .all(|(key, matched)| rank(matched, key).is_some())
    }

    /// Whether `candidate` sorts before `best`, both matching: column by column, a key before
    /// `*`, a key by its rank.
    fn better(&self, candidate: &Variant, best: &Variant) -> bool {
        let columns = candidate.keys.iter().zip(&best.keys).zip(&self.0);
        for ((a, b), matched) in columns {
            match (rank(matched, a), rank(matched, b)) {
                (Some(Some(a)), Some(Some(b))) if a != b => return a < b,
                (Some(Some(_)), Some(None)) => return true,
                (Some(None), Some(Some(_))) => return false,
                _ => {}
            }
        }
        false
    }
}

impl Compiled {
    /// The message `id` resolved over its arguments' texts.
    ///
    /// # Errors
    ///
    /// [`ResolveError`] for an argument the message does not give, or a text a function
    /// refuses.
    pub(crate) fn resolve<'a>(
        &'a self,
        id: &str,
        argument: &Argument<'a>,
        bidi: Bidi,
    ) -> Result<Text, ResolveError> {
        let pattern = match &self.body {
            Body::Pattern(pattern) => pattern,
            Body::Select {
                columns,
                variants,
                fallback,
            } => {
                let mut ranks = Vec::with_capacity(columns.len());
                for column in columns {
                    let matched = column
                        .selector
                        .select(argument, &column.keys)
                        .map_err(|failure| column.called.error(id, failure))?;
                    ranks.push(matched);
                }
                let ranks = Ranks(ranks);
                let mut best: Option<&Variant> = None;
                for variant in variants.iter().filter(|variant| ranks.matches(variant)) {
                    if best.is_none_or(|current| ranks.better(variant, current)) {
                        best = Some(variant);
                    }
                }
                best.map_or(fallback, |variant| &variant.pattern)
            }
        };
        let mut writer = Writer::default();
        for part in pattern {
            match part {
                Part::Text(text) => writer.text(text),
                Part::Open(style) => writer.open(*style),
                Part::Close(style) => writer.close(*style),
                Part::Placeholder(placeholder) => {
                    let text = placeholder
                        .formatter
                        .format(argument)
                        .map_err(|failure| placeholder.called.error(id, failure))?;
                    let direction = placeholder.formatter.direction();
                    match isolation(bidi, placeholder.dir, direction, self.direction) {
                        Some(open) => {
                            writer.text(open);
                            writer.text(&text);
                            writer.text("\u{2069}");
                        }
                        None => writer.text(&text),
                    }
                }
            }
        }
        Ok(writer.finish())
    }

    /// The keys of the arguments the message's placeholders and selectors read, each once, in
    /// order.
    #[cfg(feature = "check")]
    pub(crate) fn reads(&self) -> Vec<&str> {
        fn placeholders(pattern: &Pattern) -> impl Iterator<Item = &Called> {
            pattern.iter().filter_map(|part| match part {
                Part::Placeholder(placeholder) => Some(&placeholder.called),
                Part::Text(_) | Part::Open(_) | Part::Close(_) => None,
            })
        }
        let called: Vec<&Called> = match &self.body {
            Body::Pattern(pattern) => placeholders(pattern).collect(),
            Body::Select {
                columns,
                variants,
                fallback,
            } => columns
                .iter()
                .map(|column| &column.called)
                .chain(
                    variants
                        .iter()
                        .flat_map(|variant| placeholders(&variant.pattern)),
                )
                .chain(placeholders(fallback))
                .collect(),
        };
        let mut reads: Vec<&str> = called
            .iter()
            .flat_map(|called| called.reads.iter().map(String::as_str))
            .collect();
        reads.sort_unstable();
        reads.dedup();
        reads
    }
}
