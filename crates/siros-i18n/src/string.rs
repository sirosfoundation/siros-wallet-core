//! `:string` (spec/functions/string.md), the framework's own format: it formats a text as given
//! and selects the key equal to the text. It takes no options and ignores those a call writes,
//! as spec/functions/README.md permits.
//!
//! The keys are NFC from the parser. A selector over a literal, directly or through declarations,
//! compiles the literal's NFC form, which the selection compares; formatting writes the literal
//! as written. A selector over an argument compares the argument's text as given: the typed
//! values and the loader's checks leave run-time normalization no text to serve (decision 19).

#[cfg(feature = "load")]
use unicode_normalization::UnicodeNormalization;

#[cfg(feature = "load")]
use siros_explain::ArgKind;

#[cfg(feature = "render")]
use crate::error::{FormatFailure, RenderError};
#[cfg(feature = "load")]
use crate::error::{Refusal, RefusedOption};
use crate::format::FormatId;
#[cfg(feature = "load")]
use crate::format::{Call, FormatCompiler, LanguageFormats, Operand, ParsedFormats};
#[cfg(feature = "render")]
use crate::format::{Direction, FormatRenderer, Input, VariantKey, VariantKeys};
#[cfg(feature = "render")]
use crate::sink::Sink;

/// The `:string` format, both halves.
#[derive(Debug)]
pub(crate) struct StringFormat;

/// The one `:string` format.
pub(crate) static STRING: StringFormat = StringFormat;

/// Its identity.
const ID: FormatId = siros_explain::checked!(FormatId, "string");

#[cfg(feature = "load")]
impl FormatCompiler for StringFormat {
    fn id(&self) -> FormatId {
        ID
    }

    fn functions(&self) -> &'static [&'static str] {
        &["string"]
    }

    fn options(&self) -> &'static [&'static str] {
        &[]
    }

    fn parse(
        &self,
        _language: &LanguageFormats<'_>,
    ) -> Result<Box<dyn ParsedFormats>, RefusedOption> {
        Ok(Box::new(StringFormat))
    }
}

/// The literal a chain of `:string` calls starts from.
#[cfg(feature = "load")]
fn literal<'c>(operand: Operand<'c>) -> Option<&'c str> {
    match operand {
        Operand::Literal(literal) => Some(literal),
        Operand::Call(inner) => literal(inner.operand()),
        Operand::None | Operand::Argument(_) => None,
    }
}

/// The compiled call: the NFC form of the literal a selector compares, or no bytes, which
/// compare the operand's text as given.
#[cfg(feature = "load")]
impl ParsedFormats for StringFormat {
    fn compile(&self, call: &Call<'_>) -> Result<Vec<u8>, Refusal> {
        let text = match call.operand() {
            Operand::Literal(_) => true,
            Operand::Argument(kind) => matches!(
                kind,
                ArgKind::Name | ArgKind::Raw | ArgKind::Text | ArgKind::Message
            ),
            Operand::Call(inner) => inner.function() == "string",
            Operand::None => false,
        };
        if !text {
            return Err(Refusal::Operand);
        }
        let compared = literal(call.operand()).filter(|_| call.uses().selects());
        Ok(compared.map_or_else(Vec::new, |literal| {
            literal.nfc().collect::<String>().into_bytes()
        }))
    }
}

/// The text a `:string` operand holds.
#[cfg(feature = "render")]
fn text<'a>(input: &Input<'a>) -> Result<&'a str, RenderError> {
    match *input {
        Input::Literal(text) | Input::Text(text) => Ok(text),
        Input::None | Input::Value(_) | Input::List { .. } => {
            Err(RenderError::Message(FormatFailure::BadOperand))
        }
    }
}

#[cfg(feature = "render")]
impl FormatRenderer for StringFormat {
    fn id(&self) -> FormatId {
        ID
    }

    fn direction(&self, _compiled: &[u8], _input: &Input<'_>) -> Result<Direction, RenderError> {
        Ok(Direction::Unknown)
    }

    fn render(
        &self,
        _compiled: &[u8],
        input: &Input<'_>,
        sink: &mut dyn Sink,
    ) -> Result<(), RenderError> {
        sink.text(text(input)?);
        Ok(())
    }

    fn select<'k>(
        &self,
        compiled: &[u8],
        input: &Input<'_>,
        keys: VariantKeys<'k>,
    ) -> Result<Vec<VariantKey<'k>>, RenderError> {
        let given = text(input)?;
        let compared = if compiled.is_empty() {
            given
        } else {
            std::str::from_utf8(compiled).map_err(|_| RenderError::Compiled(ID))?
        };
        Ok(keys
            .iter()
            .filter(|(_, key)| *key == compared)
            .map(|(key, _)| key)
            .collect())
    }
}
