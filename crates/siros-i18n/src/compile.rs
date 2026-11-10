//! A message compiled for a context, and resolved. Its values form a table: each declaration's
//! value once, each literal and argument an expression reads, and each call, on an earlier value.
//! A variable stands for its declaration's value, else for the argument of its name. Each
//! placeholder and each selector names the call it formats or selects with, and each option a
//! variable gives names the value it takes; the load checks each call once for each such use. A
//! declaration nothing reads never runs. Markup opens and closes the styles in nested order.
//!
//! A message resolves lazily: a placeholder formats when the pattern writes it, a selector
//! selects when the matcher picks a variant (spec/formatting.md "Pattern Selection"), and a call
//! an option reads gives its value once per resolution.

use rustc_hash::{FxHashMap, FxHashSet};

use crate::context::Bidi;
use crate::error::{LoadError, Refusal, ResolveError, SyntaxRule};
use crate::format::{
    Argument, Call, Chain, Dir, Direction, Env, Formats, Function, OptionValue, Refused, Use, Value,
};
use crate::mf2::ast::{self, Key, MarkupKind};
use crate::normal::Hold;
use crate::text::{Style, Text, Writer};

/// A message, compiled: its module's direction, its values, and its body.
#[derive(Debug, Clone)]
pub(crate) struct Compiled {
    direction: Direction,
    values: Vec<Value>,
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

/// A selector: the index of the call it selects with, and the distinct keys of its column.
#[derive(Debug, Clone)]
struct Column {
    call: usize,
    keys: Vec<String>,
}

/// A variant with a key: one key per selector, and its pattern.
#[derive(Debug, Clone)]
struct Variant {
    keys: Vec<Key>,
    pattern: Pattern,
}

type Pattern = Vec<Part>;

/// A part of a compiled pattern: a placeholder is the index of the call it formats with.
#[derive(Debug, Clone)]
enum Part {
    Text(String),
    Placeholder(usize),
    Open(Style),
    Close(Style),
}

/// The compilation of one message: its id, its line, the context's formats, how the load holds
/// selector literals, the values so far, the value each variable stands for, and the uses of a
/// call checked so far.
struct Compiler<'c> {
    id: &'c str,
    line: usize,
    formats: &'c Formats,
    hold: Hold,
    values: Vec<Value>,
    bound: FxHashMap<String, usize>,
    checked: FxHashSet<(usize, Use)>,
}

/// Compiles the message `id`, which starts at `line` of a module whose direction is
/// `direction`, each literal a selector compares held by `hold`.
///
/// # Errors
///
/// [`LoadError`] for a function the build lacks, a function whose section no module defined, a
/// call its function refuses, a selector literal `hold` refuses, and markup outside the styles
/// or not nested.
pub(crate) fn compile(
    id: &str,
    line: usize,
    message: &ast::Message,
    direction: Direction,
    formats: &Formats,
    hold: Hold,
) -> Result<Compiled, LoadError> {
    let mut compiler = Compiler {
        id,
        line,
        formats,
        hold,
        values: Vec::new(),
        bound: FxHashMap::default(),
        checked: FxHashSet::default(),
    };
    for declaration in &message.declarations {
        let (name, at) = match declaration {
            ast::Declaration::Input {
                name,
                function: Some(function),
            } => {
                let operand = compiler.push(Value::Argument(name.clone()));
                (name, compiler.call(Some(operand), function)?)
            }
            ast::Declaration::Input {
                name,
                function: None,
            } => (name, compiler.push(Value::Argument(name.clone()))),
            ast::Declaration::Local { name, expression } => (name, compiler.bind(expression)?),
        };
        if compiler.bound.insert(name.clone(), at).is_some() {
            return Err(compiler.syntax(SyntaxRule::DuplicateDeclaration {
                id: id.to_owned(),
                variable: name.clone(),
            }));
        }
    }
    let body = match &message.body {
        ast::Body::Pattern(pattern) => Body::Pattern(compiler.pattern(pattern)?),
        ast::Body::Matcher {
            selectors,
            variants,
        } => compiler.matcher(selectors, variants)?,
    };
    Ok(Compiled {
        direction,
        values: compiler.values,
        body,
    })
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
            Refused::Unnormalized(literal) => LoadError::Unnormalized {
                id,
                text: literal.written(),
            },
        }
    }

    /// Adds a value; returns its index.
    fn push(&mut self, value: Value) -> usize {
        self.values.push(value);
        self.values.len() - 1
    }

    /// The index of the value the variable `name` stands for: its declaration's, else the
    /// argument of its name, which the variable then stands for.
    fn variable(&mut self, name: &str) -> usize {
        if let Some(&at) = self.bound.get(name) {
            return at;
        }
        let at = self.push(Value::Argument(name.to_owned()));
        *self.bound.entry(name.to_owned()).or_insert(at)
    }

    /// The index of an operand's value.
    fn operand(&mut self, operand: &ast::Operand) -> usize {
        match operand {
            ast::Operand::Literal(literal) => self.push(Value::Literal(literal.clone())),
            ast::Operand::Variable(name) => self.variable(name),
        }
    }

    /// Whether the value at `at` is a call.
    fn is_call(&self, at: usize) -> bool {
        matches!(self.values.get(at), Some(Value::Call(_)))
    }

    /// The index of the value a local declaration's expression binds.
    fn bind(&mut self, expression: &ast::Expression) -> Result<usize, LoadError> {
        match expression {
            ast::Expression::Operand {
                operand,
                function: None,
            } => Ok(self.operand(operand)),
            ast::Expression::Operand {
                operand,
                function: Some(function),
            } => {
                let operand = self.operand(operand);
                self.call(Some(operand), function)
            }
            ast::Expression::Function(function) => self.call(None, function),
        }
    }

    /// Checks the call at `at` for `used`, once per use.
    fn check(&mut self, at: usize, used: Use) -> Result<(), LoadError> {
        if !self.checked.insert((at, used)) {
            return Ok(());
        }
        let refused = |function| self.refused(function, Refused::Call(Refusal::Operand));
        let chain = Chain::of(&self.values, at).ok_or_else(|| refused(Function::String))?;
        crate::format::check(&chain, used, self.formats, self.hold)
            .map_err(|refusal| self.refused(chain.outer.function, refusal))
    }

    /// A call of `function` on the value at `operand`: its options, each a literal or a
    /// variable, and a `u:dir` the load fixes, which names a direction. Returns its index.
    fn call(
        &mut self,
        operand: Option<usize>,
        function: &ast::Function,
    ) -> Result<usize, LoadError> {
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
        let refuse = |id: &str, option: &str| LoadError::Call {
            id: id.to_owned(),
            function: name.to_owned(),
            refusal: Refusal::Option {
                option: option.to_owned(),
            },
        };
        let mut options = Vec::with_capacity(function.options.len());
        for option in &function.options {
            let value = match &option.value {
                ast::Operand::Literal(literal) => OptionValue::Literal(literal.clone()),
                ast::Operand::Variable(variable) => {
                    let at = self.variable(variable);
                    if self.is_call(at) {
                        self.check(at, Use::Value)?;
                    }
                    OptionValue::Variable(at)
                }
            };
            match option.name.as_str() {
                "u:dir" => {
                    if value
                        .fixed(&self.values)
                        .is_some_and(|text| Dir::named(text).is_none())
                    {
                        return Err(refuse(self.id, &option.name));
                    }
                }
                "u:id" => {}
                other if other.starts_with("u:") => return Err(refuse(self.id, other)),
                _ => {}
            }
            options.push((option.name.clone(), value));
        }
        Ok(self.push(Value::Call(Call {
            function: called,
            operand,
            options,
        })))
    }

    /// A placeholder: the index of the call it formats with, checked. A literal or a variable
    /// without a function formats with `:string`.
    fn placeholder(&mut self, expression: &ast::Expression) -> Result<usize, LoadError> {
        let at = match expression {
            ast::Expression::Operand {
                operand,
                function: None,
            } => {
                let at = self.operand(operand);
                if self.is_call(at) {
                    at
                } else {
                    self.push(Value::Call(Call {
                        function: Function::String,
                        operand: Some(at),
                        options: Vec::new(),
                    }))
                }
            }
            ast::Expression::Operand {
                operand,
                function: Some(function),
            } => {
                let operand = self.operand(operand);
                self.call(Some(operand), function)?
            }
            ast::Expression::Function(function) => self.call(None, function)?,
        };
        self.check(at, Use::Format)?;
        Ok(at)
    }

    /// A `.match` body: each selector checked over its column's keys, each variant's pattern,
    /// and the variant whose keys are all `*`.
    fn matcher(
        &mut self,
        selectors: &[String],
        variants: &[ast::Variant],
    ) -> Result<Body, LoadError> {
        let mut columns = Vec::with_capacity(selectors.len());
        for (column, name) in selectors.iter().enumerate() {
            let call = self.variable(name);
            if !self.is_call(call) {
                return Err(self.syntax(SyntaxRule::MissingSelectorAnnotation {
                    id: self.id.to_owned(),
                    variable: name.clone(),
                }));
            }
            let mut seen = FxHashSet::default();
            let mut keys: Vec<String> = Vec::new();
            for variant in variants {
                if let Some(Key::Literal(key)) = variant.keys.get(column)
                    && seen.insert(key.as_str())
                {
                    keys.push(key.clone());
                }
            }
            self.check(call, Use::Select)?;
            if let Some(Value::Call(selecting)) = self.values.get(call) {
                let function = selecting.function;
                crate::format::keys(function, &keys)
                    .map_err(|refusal| self.refused(function, Refused::Call(refusal)))?;
            }
            columns.push(Column { call, keys });
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
    fn pattern(&mut self, pattern: &ast::Pattern) -> Result<Pattern, LoadError> {
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
    /// The chain of the call at `at`.
    fn chain(&self, id: &str, at: usize) -> Result<Chain<'_>, ResolveError> {
        Chain::of(&self.values, at).ok_or_else(|| ResolveError::Unknown { id: id.to_owned() })
    }

    /// The message `id` resolved over its arguments' texts, with the context's format sections
    /// `formats`.
    ///
    /// # Errors
    ///
    /// [`ResolveError`] for an argument the message does not give, or a text a function
    /// refuses.
    pub(crate) fn resolve<'a>(
        &'a self,
        id: &str,
        argument: &Argument<'a>,
        formats: &'a Formats,
        bidi: Bidi,
    ) -> Result<Text, ResolveError> {
        let mut env = Env::new(argument, &self.values, formats);
        let pattern = match &self.body {
            Body::Pattern(pattern) => pattern,
            Body::Select {
                columns,
                variants,
                fallback,
            } => {
                let mut ranks = Vec::with_capacity(columns.len());
                for column in columns {
                    let chain = self.chain(id, column.call)?;
                    let texts = chain
                        .texts(&mut env)
                        .map_err(|failure| chain.error(id, failure))?;
                    let matched = crate::format::select(&chain, &texts, &env, &column.keys)
                        .map_err(|failure| chain.error(id, failure))?;
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
                Part::Placeholder(at) => {
                    let chain = self.chain(id, *at)?;
                    let texts = chain
                        .texts(&mut env)
                        .map_err(|failure| chain.error(id, failure))?;
                    let (text, direction) = crate::format::format(&chain, &texts, &env)
                        .map_err(|failure| chain.error(id, failure))?;
                    match isolation(bidi, Dir::of(&texts), direction, self.direction) {
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

    /// The keys of the arguments the message's placeholders and selectors read, through their
    /// operands and their options' variables, each once, in order.
    #[cfg(feature = "check")]
    pub(crate) fn reads(&self) -> Vec<&str> {
        fn placeholders(pattern: &Pattern) -> impl Iterator<Item = usize> + '_ {
            pattern.iter().filter_map(|part| match part {
                Part::Placeholder(at) => Some(*at),
                Part::Text(_) | Part::Open(_) | Part::Close(_) => None,
            })
        }
        let mut pending: Vec<usize> = match &self.body {
            Body::Pattern(pattern) => placeholders(pattern).collect(),
            Body::Select {
                columns,
                variants,
                fallback,
            } => columns
                .iter()
                .map(|column| column.call)
                .chain(
                    variants
                        .iter()
                        .flat_map(|variant| placeholders(&variant.pattern)),
                )
                .chain(placeholders(fallback))
                .collect(),
        };
        let mut seen = vec![false; self.values.len()];
        let mut reads: Vec<&str> = Vec::new();
        while let Some(at) = pending.pop() {
            match seen.get_mut(at) {
                Some(visited) if !*visited => *visited = true,
                Some(_) | None => continue,
            }
            match self.values.get(at) {
                Some(Value::Argument(key)) => reads.push(key),
                Some(Value::Call(call)) => {
                    pending.extend(call.operand);
                    pending.extend(call.options.iter().filter_map(|(_, value)| match value {
                        OptionValue::Variable(at) => Some(*at),
                        OptionValue::Literal(_) => None,
                    }));
                }
                Some(Value::Literal(_)) | None => {}
            }
        }
        reads.sort_unstable();
        reads.dedup();
        reads
    }
}
