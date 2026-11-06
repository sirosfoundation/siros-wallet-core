//! One suite test: its message loaded as a module of one key in the test's locale, its params
//! declared and given as the key's arguments, and its text rendered.

use serde_json::Value as Json;
use siros_explain::{
    Count, Decimal, DefinedKey, DefinedModule, Domain, Entry, Keyed, Message, MessageId,
    MetadataDigest, ModuleId, Names, ParamKind, ParamName, Query, Text, Value, checked,
};
use siros_i18n::{
    Amounts, Bidi, BuiltPackage, Declaration, Formats, Formatted, LocaleTag, Module, ModuleError,
    OnRenderError, Package, PackageBuilder, Refusal, RenderError, RenderOptions, Screen, Validity,
};

use crate::cldr;
use crate::test_function::TEST;

/// A test's result: a pass says whether its text rendered through the three packages, one
/// holding its text precomputed, one holding its key compiled and one compiled from the live
/// module.
pub enum Outcome {
    Pass { packaged: bool },
    Fail(String),
}

/// A test's message rendered, or the MF2 error type that refused it, and whether it rendered
/// through packages.
struct Rendered {
    text: Result<String, &'static str>,
    packaged: bool,
}

const KEY: &str = "conformance.message";

/// A param: its name and its value, typed as its JSON type gives it.
struct Param {
    name: &'static str,
    value: Text,
    kind: ParamKind,
}

fn param(json: &Json) -> Result<Param, String> {
    let name: &'static str = Box::leak(
        json["name"]
            .as_str()
            .ok_or("a param without a name")?
            .to_owned()
            .into_boxed_str(),
    );
    let (value, kind) = match &json["value"] {
        Json::String(text) => (Text::Raw(text.clone()), ParamKind::of::<String>()),
        Json::Number(number) if number.as_u64().is_some() => {
            let count = Count::parse(&number.to_string()).ok_or("a count")?;
            (Text::Value(Value::Count(count)), ParamKind::of::<Count>())
        }
        Json::Number(number) => {
            let text = number.to_string();
            let (negative, digits) = text
                .strip_prefix('-')
                .map_or((false, text.as_str()), |rest| (true, rest));
            let (whole, fraction) = digits.split_once('.').unwrap_or((digits, ""));
            let units: i128 = format!("{whole}{fraction}")
                .parse()
                .map_err(|_| format!("the number {text}"))?;
            let units = if negative { -units } else { units };
            let decimal = Decimal::new(units, u8::try_from(fraction.len()).map_err(|_| "a scale")?)
                .ok_or("a decimal")?;
            (
                Text::Value(Value::Decimal(decimal)),
                ParamKind::of::<Decimal>(),
            )
        }
        other => return Err(format!("a param of JSON {other}")),
    };
    Ok(Param { name, value, kind })
}

/// The declaration of the one message, its params named and kinded.
fn declaration(params: &[Param]) -> Result<Declaration, String> {
    let id: MessageId = checked!(MessageId, "conformance.message");
    let names: Vec<&'static str> = params.iter().map(|p| p.name).collect();
    let kinds: Vec<ParamKind> = params.iter().map(|p| p.kind).collect();
    macro_rules! of {
        ($n:literal) => {{
            let names: [&'static str; $n] = names.try_into().map_err(|_| "names")?;
            let names = Names::new(names).ok_or("a param name outside the tokens")?;
            Message::new(id, None, names, kinds.try_into().map_err(|_| "kinds")?)
        }};
    }
    let message = match params.len() {
        0 => of!(0),
        1 => of!(1),
        2 => of!(2),
        3 => of!(3),
        n => return Err(format!("{n} params")),
    };
    Declaration::new(vec![message]).map_err(|e| e.to_string())
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
    format!("{KEY} = {value}")
}

/// The MF2 error type a load refusal stands for.
fn module_error(error: &ModuleError) -> Option<&'static str> {
    Some(match error {
        ModuleError::Syntax { .. } => "syntax-error",
        ModuleError::Invalid { rule, .. } => match rule {
            Validity::VariantKeyMismatch => "variant-key-mismatch",
            Validity::MissingFallbackVariant => "missing-fallback-variant",
            Validity::MissingSelectorAnnotation { .. } => "missing-selector-annotation",
            Validity::DuplicateDeclaration { .. } => "duplicate-declaration",
            Validity::DuplicateOptionName { .. } => "duplicate-option-name",
            Validity::DuplicateVariant => "duplicate-variant",
        },
        ModuleError::Argument { .. } => "unresolved-variable",
        ModuleError::Function { .. } => "unknown-function",
        ModuleError::Kind { refusal, .. } => match refusal {
            Refusal::Operand => "bad-operand",
            Refusal::Option { .. } => "bad-option",
            Refusal::Selector => "bad-selector",
            Refusal::Formatter => "not-formattable",
        },
        _ => return None,
    })
}

/// The MF2 error type a render refusal stands for.
fn render_error(error: &RenderError) -> Option<&'static str> {
    match error {
        RenderError::Message(kind) => Some(kind.name()),
        RenderError::AbsentArgument { .. } => Some("unresolved-variable"),
        _ => None,
    }
}

/// A package of `module` in `tag`: every key or the test's, and the text precomputed.
fn package(
    module: &Module,
    tag: &LocaleTag,
    keys: Option<&[MessageId]>,
    held: Option<&Held<'_>>,
) -> Result<BuiltPackage, String> {
    let mut builder = PackageBuilder::new(vec![tag.clone()]).map_err(|e| e.to_string())?;
    builder.module(module, keys).map_err(|e| e.to_string())?;
    let Some(held) = held else {
        return Ok(builder.finish());
    };
    let mut texts = builder.texts(held.formats);
    match texts.precompute(held.text, held.options) {
        Ok(()) | Err(RenderError::Message(_) | RenderError::AbsentArgument { .. }) => {}
        Err(error) => return Err(format!("precompute refused for no MF2 error: {error}")),
    }
    Ok(texts.finish())
}

/// A text to precompute, with the formats and the options it renders with.
struct Held<'a> {
    text: &'a Text,
    formats: &'a Formats,
    options: RenderOptions,
}

/// The text rendered through a package's renderer in `tag`.
fn through(
    built: &BuiltPackage,
    defined: DefinedModule,
    tag: &LocaleTag,
    held: &Held<'_>,
) -> Result<Result<Formatted, RenderError>, String> {
    let package = Package::read(built.bytes(), built.root()).map_err(|e| e.to_string())?;
    let screen =
        Screen::new(&package, vec![ModuleId::Defined(defined)]).map_err(|e| e.to_string())?;
    let located = screen
        .locale(std::slice::from_ref(tag), &[])
        .map_err(|e| e.to_string())?;
    let renderer = located
        .renderer(held.formats, held.options)
        .map_err(|e| e.to_string())?;
    Ok(renderer.formatted(held.text))
}

/// Over one text: packages built twice give the same bytes, read back and written again the
/// same bytes, and the text renders byte-equal through a package that holds it precomputed, one
/// that holds its key compiled, and one compiled from the live module.
fn packaged(
    module: &Module,
    defined: DefinedModule,
    tag: &LocaleTag,
    held: &Held<'_>,
) -> Result<Result<Formatted, RenderError>, String> {
    let keys = &[checked!(MessageId, "conformance.message")][..];
    let compiled = package(module, tag, Some(keys), None)?;
    if package(module, tag, Some(keys), None)? != compiled {
        return Err("a package built twice differs".to_owned());
    }
    let package_read =
        Package::read(compiled.bytes(), compiled.root()).map_err(|e| e.to_string())?;
    if package_read.rewrite().map_err(|e| e.to_string())? != compiled {
        return Err("a package read back and written again differs".to_owned());
    }
    let precomputed = package(module, tag, None, Some(held))?;
    if package(module, tag, None, Some(held))? != precomputed {
        return Err("a package with a precomputed text built twice differs".to_owned());
    }
    let package_read =
        Package::read(precomputed.bytes(), precomputed.root()).map_err(|e| e.to_string())?;
    if package_read.rewrite().map_err(|e| e.to_string())? != precomputed {
        return Err("a package with a precomputed text written again differs".to_owned());
    }
    let live = package(module, tag, None, None)?;
    let renders = [
        through(&precomputed, defined, tag, held)?,
        through(&compiled, defined, tag, held)?,
        through(&live, defined, tag, held)?,
    ];
    match &renders {
        [first, rest @ ..] if rest.iter().all(|other| other == first) => Ok(first.clone()),
        _ => Err(format!("the packages render differently: {renders:?}")),
    }
}

/// The test's message rendered, or the MF2 error type that refused it.
fn render(locale: &str, bidi: Bidi, src: &str, params: &[Param]) -> Result<Rendered, String> {
    let declaration = declaration(params)?;
    let plugin = checked!(Domain, "conformance");
    let defined = DefinedModule::new(plugin, MetadataDigest::new([0; 32]));
    let compilers = cldr::compilers(&[&TEST]);
    let source = resource(src);
    let module = match cldr::load(
        ModuleId::Defined(defined),
        &declaration,
        locale,
        &source,
        &compilers,
    ) {
        Ok(module) => module,
        Err(error) => {
            return module_error(&error)
                .map(|error| Rendered {
                    text: Err(error),
                    packaged: false,
                })
                .ok_or(format!("refused for no MF2 error: {error}"));
        }
    };
    let tag = LocaleTag::parse(locale).map_err(|e| e.to_string())?;
    let formats = cldr::formats(&[&TEST]);
    let options = RenderOptions {
        amounts: Amounts::Formatted,
        bidi,
        on_error: OnRenderError::NoEntry,
    };
    let args = params
        .iter()
        .map(|p| {
            let name = ParamName::parse(p.name.to_owned()).ok_or("a param name")?;
            Ok(Entry::new(name, p.value.clone()))
        })
        .collect::<Result<Vec<_>, &str>>()?;
    let args = Keyed::new(args).map_err(|e| e.to_string())?;
    let key = DefinedKey::parse(KEY.to_owned()).ok_or("the key")?;
    let text = Text::Query(Query::defined(defined, key, args));
    let held = Held {
        text: &text,
        formats: &formats,
        options,
    };
    let text = match packaged(&module, defined, &tag, &held)? {
        Ok(formatted) => Ok(formatted.plain()),
        Err(error) => {
            Err(render_error(&error).ok_or(format!("refused for no MF2 error: {error}"))?)
        }
    };
    Ok(Rendered {
        text,
        packaged: true,
    })
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
        Ok(params) => params,
        Err(detail) => return Outcome::Fail(detail),
    };
    let rendered = match render(locale, bidi, src, &params) {
        Ok(rendered) => rendered,
        Err(detail) => return Outcome::Fail(detail),
    };
    let packaged = rendered.packaged;
    match (rendered.text, errors.is_empty()) {
        (Err(error), false) if errors.contains(&error) => Outcome::Pass { packaged },
        (Err(error), _) => Outcome::Fail(format!("refused with {error}, expected {errors:?}")),
        (Ok(text), false) => Outcome::Fail(format!("rendered {text:?}, expected {errors:?}")),
        (Ok(text), true) => match expected {
            Some(expected) if text != expected => {
                Outcome::Fail(format!("rendered {text:?}, expected {expected:?}"))
            }
            _ => Outcome::Pass { packaged },
        },
    }
}
