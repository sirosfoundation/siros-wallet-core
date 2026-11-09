//! MF2's data model rules (spec/syntax.md, spec/errors.md "Data Model Errors"): what makes a
//! well-formed message valid.

use crate::error::SyntaxRule;

use super::ast::{
    Body, Declaration, Expression, Function, Key, Message, Operand, Opt, Part, Pattern,
};

/// The first data model rule the message `id` breaks.
pub(crate) fn check(id: &str, message: &Message) -> Result<(), SyntaxRule> {
    let id = || id.to_owned();
    declarations(&message.declarations)
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
                .find(|selector| !annotated(&message.declarations, selector))
            {
                return Err(SyntaxRule::MissingSelectorAnnotation {
                    id: id(),
                    variable: selector.clone(),
                });
            }
            for (index, variant) in variants.iter().enumerate() {
                if variants
                    .iter()
                    .take(index)
                    .any(|earlier| earlier.keys == variant.keys)
                {
                    return Err(SyntaxRule::DuplicateVariant { id: id() });
                }
            }
            variants
                .iter()
                .try_for_each(|variant| pattern_options(&variant.pattern))
                .map_err(repeated)
        }
    }
}

/// Duplicate Declaration: a declaration binds no variable a previous declaration names, and none
/// its own expression or function names. The error is the variable.
fn declarations(declarations: &[Declaration]) -> Result<(), String> {
    let mut named: Vec<&str> = Vec::new();
    for declaration in declarations {
        let (bound, mut own) = match declaration {
            Declaration::Input { name, function } => {
                let mut own = Vec::new();
                if let Some(function) = function {
                    function_variables(function, &mut own);
                }
                (name.as_str(), own)
            }
            Declaration::Local { name, expression } => {
                let mut own = Vec::new();
                expression_variables(expression, &mut own);
                (name.as_str(), own)
            }
        };
        if named.contains(&bound) || own.contains(&bound) {
            return Err(bound.to_owned());
        }
        named.push(bound);
        named.append(&mut own);
    }
    Ok(())
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

/// Missing Selector Annotation: the selector references, directly or through local
/// declarations, a declaration with a function.
fn annotated(declarations: &[Declaration], variable: &str) -> bool {
    let mut name = variable;
    for declaration in declarations.iter().rev() {
        match declaration {
            Declaration::Input {
                name: bound,
                function,
            } if bound == name => return function.is_some(),
            Declaration::Local {
                name: bound,
                expression,
            } if bound == name => match expression {
                Expression::Operand {
                    function: Some(_), ..
                }
                | Expression::Function(_) => return true,
                Expression::Operand {
                    operand: Operand::Variable(next),
                    function: None,
                } => name = next,
                Expression::Operand {
                    operand: Operand::Literal(_),
                    function: None,
                } => return false,
            },
            _ => {}
        }
    }
    false
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
    for (index, option) in options.iter().enumerate() {
        if options
            .iter()
            .take(index)
            .any(|earlier| earlier.name == option.name)
        {
            return Err(option.name.clone());
        }
    }
    Ok(())
}
