//! MF2's data model rules (spec/syntax.md, spec/errors.md "Data Model Errors"): a [`Valid`] is a
//! well-formed message they hold for.

use std::borrow::Cow;

use rustc_hash::FxHashSet;

use crate::error::Fault;
use crate::seen::repeated;

use super::ast::{
    Body, Declaration, Expression, Function, Key, Message, Operand, Opt, Part, Pattern, Variant,
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
    /// `.match`: its selectors, each a variable a declaration with a function binds; its variants
    /// with a literal key, each of one key per selector and each list of keys once; and the
    /// pattern of the one variant whose keys are all `*`.
    Matcher {
        selectors: &'a [Cow<'s, str>],
        variants: Vec<&'a Variant<'s>>,
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
        let annotated = declarations(&message.declarations)?;
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
                let catches_all =
                    |variant: &Variant<'_>| variant.keys.iter().all(|key| *key == Key::CatchAll);
                if variants.iter().any(|v| v.keys.len() != selectors.len()) {
                    return Err(Fault::VariantKeyMismatch);
                }
                let fallback = variants
                    .iter()
                    .find(|variant| catches_all(variant))
                    .ok_or(Fault::MissingFallbackVariant)?;
                if let Some(selector) = selectors
                    .iter()
                    .find(|selector| !annotated.contains(selector.as_ref()))
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
                    variants: variants.iter().filter(|v| !catches_all(v)).collect(),
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
/// or through local declarations, a declaration with a function (Missing Selector Annotation).
fn declarations<'a>(declarations: &'a [Declaration<'_>]) -> Result<FxHashSet<&'a str>, Fault> {
    let mut bound: FxHashSet<&str> = FxHashSet::default();
    let mut annotated: FxHashSet<&str> = FxHashSet::default();
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
        let with = match declaration {
            Declaration::Input { function, .. } => function.is_some(),
            Declaration::Local {
                expression:
                    Expression::Function(_)
                    | Expression::Operand {
                        function: Some(_), ..
                    },
                ..
            } => true,
            Declaration::Local {
                expression:
                    Expression::Operand {
                        operand: Operand::Variable(next),
                        function: None,
                    },
                ..
            } => annotated.contains(next.as_ref()),
            Declaration::Local {
                expression:
                    Expression::Operand {
                        operand: Operand::Literal(_),
                        function: None,
                    },
                ..
            } => false,
        };
        let own = || variables(operand, function);
        if named.contains(name) || own().any(|own| own == name) || !bound.insert(name) {
            return Err(Fault::DuplicateDeclaration(name.to_owned()));
        }
        named.extend(own());
        if with {
            annotated.extend([name]);
        }
    }
    Ok(annotated)
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
