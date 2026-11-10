//! MF2's data model rules (spec/syntax.md, spec/errors.md "Data Model Errors"): what makes a
//! well-formed message valid.

use rustc_hash::{FxHashMap, FxHashSet};

use crate::error::SyntaxRule;
use crate::store::Id;

use super::ast::{
    Body, Declaration, Expression, Function, Key, Message, Operand, Opt, Part, Pattern,
};

/// The first data model rule the message `id` breaks.
pub(crate) fn check(id: Id<'_>, message: &Message) -> Result<(), SyntaxRule> {
    let id = || id.to_string();
    let annotated = declarations(&message.declarations)
        .map_err(|variable| SyntaxRule::DuplicateDeclaration { id: id(), variable })?;
    let repeated = |option| SyntaxRule::DuplicateOptionName { id: id(), option };
    for declaration in &message.declarations {
        match declaration {
            Declaration::Input { function, .. } => function
                .iter()
                .try_for_each(|f| options(&f.options))
                .map_err(repeated)?,
            Declaration::Local { expression, .. } => {
                expression_options(expression).map_err(repeated)?;
            }
        }
    }
    match &message.body {
        Body::Pattern(pattern) => pattern_options(pattern).map_err(repeated),
        Body::Matcher {
            selectors,
            variants,
        } => {
            if variants.iter().any(|v| v.keys.len() != selectors.len()) {
                return Err(SyntaxRule::VariantKeyMismatch { id: id() });
            }
            if !variants
                .iter()
                .any(|v| v.keys.iter().all(|key| *key == Key::CatchAll))
            {
                return Err(SyntaxRule::MissingFallbackVariant { id: id() });
            }
            if let Some(selector) = selectors
                .iter()
                .find(|selector| annotated.get(selector.as_str()) != Some(&true))
            {
                return Err(SyntaxRule::MissingSelectorAnnotation {
                    id: id(),
                    variable: selector.clone(),
                });
            }
            let mut keys: FxHashSet<&[Key]> = FxHashSet::default();
            if !variants.iter().all(|variant| keys.insert(&variant.keys)) {
                return Err(SyntaxRule::DuplicateVariant { id: id() });
            }
            variants
                .iter()
                .try_for_each(|variant| pattern_options(&variant.pattern))
                .map_err(repeated)
        }
    }
}

/// Duplicate Declaration: a declaration binds no variable a previous declaration binds or names,
/// and none its own expression or function names. The error is the variable. Returns each bound
/// variable with whether it references, directly or through local declarations, a declaration
/// with a function (Missing Selector Annotation).
fn declarations(declarations: &[Declaration]) -> Result<FxHashMap<&str, bool>, String> {
    let mut annotated: FxHashMap<&str, bool> = FxHashMap::default();
    let mut named: FxHashSet<&str> = FxHashSet::default();
    for declaration in declarations {
        let mut own = Vec::new();
        let (bound, with) = match declaration {
            Declaration::Input { name, function } => {
                if let Some(function) = function {
                    function_variables(function, &mut own);
                }
                (name.as_str(), function.is_some())
            }
            Declaration::Local { name, expression } => {
                expression_variables(expression, &mut own);
                let with = match expression {
                    Expression::Operand {
                        function: Some(_), ..
                    }
                    | Expression::Function(_) => true,
                    Expression::Operand {
                        operand: Operand::Variable(next),
                        function: None,
                    } => annotated.get(next.as_str()) == Some(&true),
                    Expression::Operand {
                        operand: Operand::Literal(_),
                        function: None,
                    } => false,
                };
                (name.as_str(), with)
            }
        };
        if named.contains(bound) || own.contains(&bound) || annotated.insert(bound, with).is_some()
        {
            return Err(bound.to_owned());
        }
        named.extend(own);
    }
    Ok(annotated)
}

fn expression_variables<'m>(expression: &'m Expression, out: &mut Vec<&'m str>) {
    let (operand, function) = expression.parts();
    if let Some(Operand::Variable(name)) = operand {
        out.push(name);
    }
    if let Some(function) = function {
        function_variables(function, out);
    }
}

fn function_variables<'m>(function: &'m Function, out: &mut Vec<&'m str>) {
    for option in &function.options {
        if let Operand::Variable(name) = &option.value {
            out.push(name);
        }
    }
}

/// Duplicate Option Name, over a pattern's expressions and markup. The error is the option.
fn pattern_options(pattern: &Pattern) -> Result<(), String> {
    pattern.iter().try_for_each(|part| match part {
        Part::Text(_) => Ok(()),
        Part::Expression(expression) => expression_options(expression),
        Part::Markup(markup) => options(&markup.options),
    })
}

fn expression_options(expression: &Expression) -> Result<(), String> {
    expression
        .parts()
        .1
        .map_or(Ok(()), |function| options(&function.options))
}

fn options(options: &[Opt]) -> Result<(), String> {
    let mut names: FxHashSet<&str> = FxHashSet::default();
    match options
        .iter()
        .find(|option| !names.insert(option.name.as_str()))
    {
        Some(option) => Err(option.name.clone()),
        None => Ok(()),
    }
}
