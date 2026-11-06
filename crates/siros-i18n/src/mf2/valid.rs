//! MF2's data model rules (spec/syntax.md, spec/errors.md "Data Model Errors"): what makes a
//! well-formed message valid.

use crate::error::Validity;

use super::ast::{
    Body, Declaration, Expression, Function, Key, Message, Operand, Opt, Part, Pattern,
};

/// The first data model rule the message breaks.
pub(crate) fn check(message: &Message) -> Result<(), Validity> {
    declarations(&message.declarations)?;
    for declaration in &message.declarations {
        match declaration {
            Declaration::Input { function, .. } => {
                function.iter().try_for_each(|f| options(&f.options))?
            }
            Declaration::Local { expression, .. } => expression_options(expression)?,
        }
    }
    match &message.body {
        Body::Pattern(pattern) => pattern_options(pattern),
        Body::Matcher {
            selectors,
            variants,
        } => {
            for variant in variants {
                if variant.keys.len() != selectors.len() {
                    return Err(Validity::VariantKeyMismatch);
                }
            }
            if !variants
                .iter()
                .any(|v| v.keys.iter().all(|key| *key == Key::CatchAll))
            {
                return Err(Validity::MissingFallbackVariant);
            }
            for selector in selectors {
                if !annotated(&message.declarations, selector) {
                    return Err(Validity::MissingSelectorAnnotation {
                        variable: selector.clone(),
                    });
                }
            }
            for (index, variant) in variants.iter().enumerate() {
                if variants
                    .iter()
                    .take(index)
                    .any(|earlier| earlier.keys == variant.keys)
                {
                    return Err(Validity::DuplicateVariant);
                }
            }
            variants
                .iter()
                .try_for_each(|variant| pattern_options(&variant.pattern))
        }
    }
}

/// Duplicate Declaration: a declaration binds no variable a previous declaration names, and none
/// its own expression or function names.
fn declarations(declarations: &[Declaration]) -> Result<(), Validity> {
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
            return Err(Validity::DuplicateDeclaration {
                variable: bound.to_owned(),
            });
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

/// Duplicate Option Name, over a pattern's expressions and markup.
fn pattern_options(pattern: &Pattern) -> Result<(), Validity> {
    pattern.iter().try_for_each(|part| match part {
        Part::Text(_) => Ok(()),
        Part::Expression(expression) => expression_options(expression),
        Part::Markup(markup) => options(&markup.options),
    })
}

fn expression_options(expression: &Expression) -> Result<(), Validity> {
    expression
        .parts()
        .1
        .map_or(Ok(()), |function| options(&function.options))
}

fn options(options: &[Opt]) -> Result<(), Validity> {
    for (index, option) in options.iter().enumerate() {
        if options
            .iter()
            .take(index)
            .any(|earlier| earlier.name == option.name)
        {
            return Err(Validity::DuplicateOptionName {
                option: option.name.clone(),
            });
        }
    }
    Ok(())
}
