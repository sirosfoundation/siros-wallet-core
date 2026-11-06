//! The number module (spec/functions/number.md): `:number` and `:integer`, which format a number
//! with the language's decimal pattern and select on exact keys, then plural categories.

use siros_explain::checked;

#[cfg(feature = "load")]
use crate::error::RefusedOption;
use crate::error::RenderError;
use crate::format::{Direction, FormatId, FormatRenderer, Input, VariantKey, VariantKeys};
#[cfg(feature = "load")]
use crate::format::{FormatCompiler, LanguageFormats, ParsedFormats};
use crate::numeric;
use crate::sink::Sink;

/// The number module, both halves.
#[derive(Debug)]
pub struct NumberFormat;

/// The number module a build registers.
pub static NUMBER: NumberFormat = NumberFormat;

const ID: FormatId = checked!(FormatId, "number");

#[cfg(feature = "load")]
impl FormatCompiler for NumberFormat {
    fn id(&self) -> FormatId {
        ID
    }

    fn functions(&self) -> &'static [&'static str] {
        &["number", "integer"]
    }

    fn options(&self) -> &'static [&'static str] {
        &numeric::compile::PLAIN
    }

    fn parse(
        &self,
        language: &LanguageFormats<'_>,
    ) -> Result<Box<dyn ParsedFormats>, RefusedOption> {
        numeric::compile::Plain::parse(language)
    }
}

impl FormatRenderer for NumberFormat {
    fn id(&self) -> FormatId {
        ID
    }

    fn direction(&self, compiled: &[u8], _input: &Input<'_>) -> Result<Direction, RenderError> {
        numeric::direction(compiled, ID)
    }

    fn render(
        &self,
        compiled: &[u8],
        input: &Input<'_>,
        sink: &mut dyn Sink,
    ) -> Result<(), RenderError> {
        numeric::render(ID, compiled, input, sink)
    }

    fn select<'k>(
        &self,
        compiled: &[u8],
        input: &Input<'_>,
        keys: VariantKeys<'k>,
    ) -> Result<Vec<VariantKey<'k>>, RenderError> {
        numeric::select(ID, compiled, input, keys)
    }
}
