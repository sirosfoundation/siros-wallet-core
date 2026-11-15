//! MF2's data model rules (spec/syntax.md, spec/errors.md "Data Model Errors"): a [`Valid`] is a
//! well-formed message they hold for.

use std::borrow::Cow;

use rustc_hash::FxHashSet;

use crate::error::Fault;
use crate::seen::repeated;

use super::ast::{
    Body, Declaration, Expression, Function, Message, Operand, Opt, Part, Pattern, Variant,
};

/// A message the data model rules hold for: each declaration binds a variable no earlier
/// declaration binds or names, and each call and each markup gives an option once.
pub(crate) struct Valid<'a, 's> {
    pub(crate) declarations: &'a [Declaration<'s>],
    pub(crate) body: Shape<'a, 's>,
}

/// A valid message's body.
pub(crate) enum Shape<'a, 's> {
    /// A single pattern.
    Pattern(&'a Pattern<'s>),
    /// `.match`: its selectors, each a variable a declaration with a function binds; its
    /// variants, each of one key per selector and each list of keys once; and among them the
    /// pattern of the one whose keys are all `*`.
    Matcher {
        selectors: &'a [Cow<'s, str>],
        variants: &'a [Variant<'s>],
        fallback: &'a Pattern<'s>,
    },
}

impl<'a, 's> Valid<'a, 's> {
    /// The message, valid.
    ///
    /// # Errors
    ///
    /// The [`Fault`] of the first data model rule the message breaks.
    pub(crate) fn of(message: &'a Message<'s>) -> Result<Self, Fault> {
        let constant = declarations(&message.declarations)?;
        for declaration in &message.declarations {
            let function = match declaration {
                Declaration::Input { function, .. } => function.as_ref(),
                Declaration::Local { expression, .. } => expression.parts().1,
            };
            function.map_or(Ok(()), |function| options(&function.options))?;
        }
        let body = match &message.body {
            Body::Pattern(pattern) => {
                pattern_options(pattern)?;
                Shape::Pattern(pattern)
            }
            Body::Matcher {
                selectors,
                variants,
            } => {
                if variants.iter().any(|v| v.keys.len() != selectors.len()) {
                    return Err(Fault::VariantKeyMismatch);
                }
                let fallback = variants
                    .iter()
                    .find(|variant| variant.catches_all())
                    .ok_or(Fault::MissingFallbackVariant)?;
                if let Some(selector) = selectors
                    .iter()
                    .find(|selector| constant.contains(selector.as_ref()))
                {
                    return Err(Fault::MissingSelectorAnnotation(selector.to_string()));
                }
                if repeated(variants.iter().map(|variant| variant.keys.as_slice())).is_some() {
                    return Err(Fault::DuplicateVariant);
                }
                variants
                    .iter()
                    .try_for_each(|variant| pattern_options(&variant.pattern))?;
                Shape::Matcher {
                    selectors,
                    variants,
                    fallback: &fallback.pattern,
                }
            }
        };
        Ok(Self {
            declarations: &message.declarations,
            body,
        })
    }
}

/// Duplicate Declaration: a declaration binds no variable a previous declaration binds or names,
/// and none its own expression or function names. Returns the variables that reference, directly
/// or through local declarations, a literal without a function, which a selector cannot select
/// by (Missing Selector Annotation). A selector over an argument selects by the default
/// formatter of the argument's type.
fn declarations<'a>(declarations: &'a [Declaration<'_>]) -> Result<FxHashSet<&'a str>, Fault> {
    let mut bound: FxHashSet<&str> = FxHashSet::default();
    let mut constant: FxHashSet<&str> = FxHashSet::default();
    let mut named: FxHashSet<&str> = FxHashSet::default();
    for declaration in declarations {
        let (name, operand, function) = match declaration {
            Declaration::Input { name, function } => (name, None, function.as_ref()),
            Declaration::Local { name, expression } => {
                let (operand, function) = expression.parts();
                (name, operand, function)
            }
        };
        let name = name.as_ref();
        let literal = match declaration {
            Declaration::Input { .. }
            | Declaration::Local {
                expression:
                    Expression::Function(_)
                    | Expression::Operand {
                        function: Some(_), ..
                    },
                ..
            } => false,
            Declaration::Local {
                expression:
                    Expression::Operand {
                        operand: Operand::Variable(next),
                        function: None,
                    },
                ..
            } => constant.contains(next.as_ref()),
            Declaration::Local {
                expression:
                    Expression::Operand {
                        operand: Operand::Literal(_),
                        function: None,
                    },
                ..
            } => true,
        };
        let own = || variables(operand, function);
        if named.contains(name) || own().any(|own| own == name) || !bound.insert(name) {
            return Err(Fault::DuplicateDeclaration(name.to_owned()));
        }
        named.extend(own());
        if literal {
            constant.extend([name]);
        }
    }
    Ok(constant)
}

/// The variable an operand names.
fn variable<'a>(operand: &'a Operand<'_>) -> Option<&'a str> {
    match operand {
        Operand::Variable(name) => Some(name.as_ref()),
        Operand::Literal(_) => None,
    }
}

/// The variables an expression's operand and its function's options name.
fn variables<'a>(
    operand: Option<&'a Operand<'_>>,
    function: Option<&'a Function<'_>>,
) -> impl Iterator<Item = &'a str> {
    let options = function
        .into_iter()
        .flat_map(|function| &function.options)
        .filter_map(|option| variable(&option.value));
    operand.and_then(variable).into_iter().chain(options)
}

/// Duplicate Option Name, over a pattern's expressions and markup.
fn pattern_options(pattern: &Pattern<'_>) -> Result<(), Fault> {
    pattern.iter().try_for_each(|part| match part {
        Part::Text(_) => Ok(()),
        Part::Expression(Expression::Function(function))
        | Part::Expression(Expression::Operand {
            function: Some(function),
            ..
        }) => options(&function.options),
        Part::Expression(Expression::Operand { function: None, .. }) => Ok(()),
        Part::Markup(markup) => options(&markup.options),
    })
}

/// Duplicate Option Name: the first option an earlier one names.
fn options(options: &[Opt<'_>]) -> Result<(), Fault> {
    match repeated(options.iter().map(|option| option.name.as_ref())) {
        Some(name) => Err(Fault::DuplicateOptionName(name.to_owned())),
        None => Ok(()),
    }
}
