//! One suite test: its message loaded as the one message of a module in the test's locale, after
//! the CLDR tool's format module of its language, and resolved over its params.

use std::fmt::Display;

use serde_json::Value as Json;
use siros_i18n::{Bidi, LoadError, Message, Refusal, ResolveError, SyntaxRule};

use crate::cldr;

/// A test's result.
pub enum Outcome {
    Pass,
    Fail(String),
}

const ID: &str = "conformance.message";

/// The test's params: each name and its value's text, a JSON number as written.
struct Params(Vec<(String, String)>);

impl Message for Params {
    fn id(&self) -> &str {
        ID
    }

    fn args(&self, arg: &mut dyn FnMut(&str, &dyn Display)) {
        for (name, text) in &self.0 {
            arg(name, text);
        }
    }
}

fn param(json: &Json) -> Result<(String, String), String> {
    let name = json["name"].as_str().ok_or("a param without a name")?;
    let text = match &json["value"] {
        Json::String(text) => text.clone(),
        Json::Number(number) => number.to_string(),
        other => return Err(format!("a param of JSON {other}")),
    };
    Ok((name.to_owned(), text))
}

/// The resource entry of a message: every character the resource format would trim or read as
/// an escape is escaped, so the value is the message as written.
fn resource(src: &str) -> String {
    let mut value = String::new();
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.peek() {
                Some('\\' | '{' | '|' | '}') => {
                    value.push('\\');
                    value.push(chars.next().expect("the peeked character"));
                }
                _ => value.push_str("\\x5C"),
            },
            '\n' => value.push_str("\\n"),
            '\r' => value.push_str("\\r"),
            '\t' => value.push_str("\\t"),
            ' ' => value.push_str("\\ "),
            c if matches!(c, '\u{0}'..='\u{1F}' | '\u{7F}'..='\u{9F}' | '\u{2028}' | '\u{2029}') => {
                value.push_str(&format!("\\U{:06X}", u32::from(c)));
            }
            c => value.push(c),
        }
    }
    format!("{ID} = {value}")
}

/// The MF2 error type a load refusal stands for; `None` for a refusal of the harness's module.
fn load_error(error: &LoadError) -> Option<&'static str> {
    Some(match error {
        LoadError::Syntax { rule, .. } => match rule {
            SyntaxRule::Message { .. } => "syntax-error",
            SyntaxRule::VariantKeyMismatch { .. } => "variant-key-mismatch",
            SyntaxRule::MissingFallbackVariant { .. } => "missing-fallback-variant",
            SyntaxRule::MissingSelectorAnnotation { .. } => "missing-selector-annotation",
            SyntaxRule::DuplicateDeclaration { .. } => "duplicate-declaration",
            SyntaxRule::DuplicateOptionName { .. } => "duplicate-option-name",
            SyntaxRule::DuplicateVariant { .. } => "duplicate-variant",
            _ => return None,
        },
        LoadError::Function { .. } => "unknown-function",
        LoadError::Call { refusal, .. } => match refusal {
            Refusal::Operand => "bad-operand",
            Refusal::Option { .. } => "bad-option",
            Refusal::Key { .. } => "bad-variant-key",
            Refusal::Selector => "bad-selector",
            Refusal::Formatter => "not-formattable",
        },
        _ => return None,
    })
}

/// The MF2 error type a resolution refusal stands for; `None` for a refusal of the harness's
/// message.
fn resolve_error(error: &ResolveError) -> Option<&'static str> {
    Some(match error {
        ResolveError::Unresolved { .. } => "unresolved-variable",
        ResolveError::Operand { .. } => "bad-operand",
        ResolveError::Option { .. } => "bad-option",
        _ => return None,
    })
}

/// The test's message resolved as plain text, or the MF2 error type that refused it.
fn resolve(
    locale: &str,
    bidi: Bidi,
    src: &str,
    params: Params,
) -> Result<Result<String, &'static str>, String> {
    let context = match cldr::context(locale, bidi, &resource(src)) {
        Ok(context) => context,
        Err(error) => {
            return load_error(&error)
                .map(Err)
                .ok_or(format!("refused for no MF2 error: {error}"));
        }
    };
    match context.resolve(&params) {
        Ok(text) => Ok(Ok(text.to_string())),
        Err(error) => resolve_error(&error)
            .map(Err)
            .ok_or(format!("refused for no MF2 error: {error}")),
    }
}

/// Runs one test under its suite's defaults.
pub fn run(defaults: &Json, test: &Json) -> Outcome {
    let get = |name: &str| test.get(name).or_else(|| defaults.get(name));
    let src = get("src").and_then(Json::as_str).unwrap_or_default();
    let locale = get("locale").and_then(Json::as_str).unwrap_or("en-US");
    let bidi = match get("bidiIsolation").and_then(Json::as_str) {
        Some("none") => Bidi::None,
        _ => Bidi::Default,
    };
    let errors: Vec<&str> = get("expErrors")
        .and_then(Json::as_array)
        .map(|errors| errors.iter().filter_map(|e| e["type"].as_str()).collect())
        .unwrap_or_default();
    let expected = get("exp").and_then(Json::as_str);
    let params = get("params")
        .and_then(Json::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let params = match params.iter().map(param).collect::<Result<Vec<_>, _>>() {
        Ok(params) => Params(params),
        Err(detail) => return Outcome::Fail(detail),
    };
    let text = match resolve(locale, bidi, src, params) {
        Ok(text) => text,
        Err(detail) => return Outcome::Fail(detail),
    };
    match (text, errors.is_empty()) {
        (Err(error), false) if errors.contains(&error) => Outcome::Pass,
        (Err(error), _) => Outcome::Fail(format!("refused with {error}, expected {errors:?}")),
        (Ok(text), false) => Outcome::Fail(format!("resolved {text:?}, expected {errors:?}")),
        (Ok(text), true) => match expected {
            Some(expected) if text != expected => {
                Outcome::Fail(format!("resolved {text:?}, expected {expected:?}"))
            }
            _ => Outcome::Pass,
        },
    }
}
