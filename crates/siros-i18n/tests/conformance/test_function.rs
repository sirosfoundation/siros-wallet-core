//! The suite's test functions `:test:function`, `:test:select` and `:test:format`
//! (test/README.md "Test Functions"), as one format module of both halves.

use siros_explain::{ArgKind, Value, checked};
use siros_i18n::{
    Call, Direction, FormatCompiler, FormatFailure, FormatId, FormatRenderer, Input,
    LanguageFormats, Operand, ParsedFormats, Refusal, RefusedOption, RenderError, Sink, VariantKey,
    VariantKeys,
};

/// The module.
pub struct TestFunctions;

/// The one instance a build registers.
pub static TEST: TestFunctions = TestFunctions;

const ID: FormatId = checked!(FormatId, "test");

/// A resolved `:test:*` expression's `DecimalPlaces`, `FailsFormat` and `FailsSelect`.
#[derive(Debug, Clone, Copy, Default)]
struct State {
    places: u8,
    fails_format: bool,
    fails_select: bool,
}

/// `number-literal` (spec/functions/number.md).
fn number_literal(text: &str) -> bool {
    let rest = text.strip_prefix('-').unwrap_or(text);
    let digits = |s: &str| s.bytes().take_while(u8::is_ascii_digit).count();
    let whole = digits(rest);
    if whole == 0 || (whole > 1 && rest.starts_with('0')) {
        return false;
    }
    let mut rest = &rest[whole..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let n = digits(fraction);
        if n == 0 {
            return false;
        }
        rest = &fraction[n..];
    }
    if let Some(exponent) = rest.strip_prefix(['e', 'E']) {
        let exponent = exponent.strip_prefix(['-', '+']).unwrap_or(exponent);
        let n = digits(exponent);
        return n > 0 && n == exponent.len();
    }
    rest.is_empty()
}

/// The state of a call, its earlier `:test:*` calls first.
fn state(call: &Call<'_>) -> Result<State, Refusal> {
    let mut state = match call.operand() {
        Operand::Call(inner) if inner.function().starts_with("test:") => state(inner)?,
        Operand::Literal(literal) if number_literal(literal) => State::default(),
        Operand::Argument(ArgKind::Count | ArgKind::Decimal) => State::default(),
        Operand::None | Operand::Literal(_) | Operand::Argument(_) | Operand::Call(_) => {
            return Err(Refusal::Operand);
        }
    };
    for option in call.options().entries() {
        let refuse = || Refusal::Option {
            option: (*option.key()).to_owned(),
        };
        match (*option.key(), *option.value()) {
            ("decimalPlaces", "0") => state.places = 0,
            ("decimalPlaces", "1") => state.places = 1,
            ("decimalPlaces", _) => return Err(refuse()),
            ("fails", "never") => {}
            ("fails", "always") => (state.fails_format, state.fails_select) = (true, true),
            ("fails", "format") => state.fails_format = true,
            ("fails", "select") => state.fails_select = true,
            ("fails", _) => return Err(refuse()),
            _ => {}
        }
    }
    Ok(state)
}

impl FormatCompiler for TestFunctions {
    fn id(&self) -> FormatId {
        ID
    }

    fn functions(&self) -> &'static [&'static str] {
        &["test:function", "test:select", "test:format"]
    }

    fn options(&self) -> &'static [&'static str] {
        &[]
    }

    fn parse(
        &self,
        _language: &LanguageFormats<'_>,
    ) -> Result<Box<dyn ParsedFormats>, RefusedOption> {
        Ok(Box::new(TestFunctions))
    }
}

impl ParsedFormats for TestFunctions {
    fn compile(&self, call: &Call<'_>) -> Result<Vec<u8>, Refusal> {
        let state = state(call)?;
        let uses = call.uses();
        if uses.formats() && call.function() == "test:select" {
            return Err(Refusal::Formatter);
        }
        if uses.formats() && state.fails_format {
            return Err(Refusal::Option {
                option: "fails".to_owned(),
            });
        }
        if uses.selects() && (call.function() == "test:format" || state.fails_select) {
            return Err(Refusal::Selector);
        }
        Ok(vec![state.places])
    }
}

/// The input's numerical value.
fn number(input: &Input<'_>) -> Result<f64, RenderError> {
    match input {
        Input::Literal(literal) => literal
            .parse()
            .map_err(|_| RenderError::Message(FormatFailure::BadOperand)),
        Input::Value(Value::Count(count)) => count
            .digits()
            .parse()
            .map_err(|_| RenderError::Message(FormatFailure::BadOperand)),
        Input::Value(Value::Decimal(decimal)) => {
            let scale = i32::from(decimal.scale());
            Ok(decimal.units() as f64 / 10f64.powi(scale))
        }
        _ => Err(RenderError::Message(FormatFailure::BadOperand)),
    }
}

impl FormatRenderer for TestFunctions {
    fn id(&self) -> FormatId {
        ID
    }

    fn direction(&self, _compiled: &[u8], _input: &Input<'_>) -> Result<Direction, RenderError> {
        Ok(Direction::Unknown)
    }

    fn render(
        &self,
        compiled: &[u8],
        input: &Input<'_>,
        sink: &mut dyn Sink,
    ) -> Result<(), RenderError> {
        let value = number(input)?;
        if value < 0.0 {
            sink.text("-");
        }
        let whole = value.abs().floor();
        sink.text(&format!("{whole}"));
        if compiled.first() == Some(&1) {
            let digit = ((value.abs() - whole) * 10.0).floor();
            sink.text(&format!(".{digit}"));
        }
        Ok(())
    }

    fn select<'k>(
        &self,
        compiled: &[u8],
        input: &Input<'_>,
        keys: VariantKeys<'k>,
    ) -> Result<Vec<VariantKey<'k>>, RenderError> {
        if number(input)? != 1.0 {
            return Ok(Vec::new());
        }
        let accepted: &[&str] = if compiled.first() == Some(&1) {
            &["1.0", "1"]
        } else {
            &["1"]
        };
        let mut matched = Vec::new();
        for text in accepted {
            matched.extend(
                keys.iter()
                    .filter(|(_, key)| key == text)
                    .map(|(key, _)| key),
            );
        }
        Ok(matched)
    }
}
