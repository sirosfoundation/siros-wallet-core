//! The byte form of a package's compiled messages, compiled calls and formatted texts: written when
//! the wallet builds a package, read when an entry is read.

use siros_explain::{ArgKind, DefinedKey, Presence};

use crate::bytes::Reader;
use crate::bytes::Writer;
use crate::error::PackageError;
use crate::form::{
    BareCalls, BareKind, BodyForm, CompiledCall, Dir, Expression, KeyRef, MessageForm, ParamForm,
    ParamName, PartForm, Root, SelectorForm, VariantForm,
};
use crate::format::Direction;
use crate::locale::LocaleTag;
use crate::sink::{Formatted, FormattedSink, Sink, Style};

/// A reader of one entry's bytes.
pub(super) type EntryReader<'a> = Reader<'a, PackageError>;

/// A reader of entry `index`, which refuses a malformed item with [`PackageError::Malformed`].
pub(super) const fn reader(bytes: &[u8], index: usize) -> EntryReader<'_> {
    Reader::of(bytes, PackageError::Malformed { entry: index })
}

/// An item read from its byte or count, `None` for another.
fn item<T>(reader: &EntryReader<'_>, read: Option<T>) -> Result<T, PackageError> {
    read.ok_or(reader.malformed())
}

/// The items of a counted list, each read by `read`.
pub(super) fn list<'a, T>(
    reader: &mut EntryReader<'a>,
    mut read: impl FnMut(&mut EntryReader<'a>) -> Result<T, PackageError>,
) -> Result<Vec<T>, PackageError> {
    let count = reader.count()?;
    (0..count).map(|_| read(reader)).collect()
}

/// Writes a counted list, each item by `write`.
pub(super) fn write_list<T>(
    writer: &mut Writer,
    items: &[T],
    mut write: impl FnMut(&mut Writer, &T),
) {
    writer.count(items.len());
    for item in items {
        write(writer, item);
    }
}

/// An owned text.
pub(super) fn text(reader: &mut EntryReader<'_>) -> Result<String, PackageError> {
    reader.text().map(str::to_owned)
}

/// A language tag.
pub(super) fn tag(reader: &mut EntryReader<'_>) -> Result<LocaleTag, PackageError> {
    let text = reader.text()?;
    LocaleTag::parse(text).map_err(|_| reader.malformed())
}

/// 32 bytes.
pub(super) fn digest(reader: &mut EntryReader<'_>) -> Result<[u8; 32], PackageError> {
    let bytes = reader.take(32)?;
    bytes.try_into().map_err(|_| reader.malformed())
}

const fn direction_byte(direction: Direction) -> u8 {
    match direction {
        Direction::Ltr => 0,
        Direction::Rtl => 1,
        Direction::Unknown => 2,
    }
}

/// A direction.
pub(super) fn direction(reader: &mut EntryReader<'_>) -> Result<Direction, PackageError> {
    let all = [Direction::Ltr, Direction::Rtl, Direction::Unknown];
    by_byte(reader, &all, direction_byte)
}

/// Writes a direction.
pub(crate) fn write_direction(writer: &mut Writer, direction: Direction) {
    writer.byte(direction_byte(direction));
}

/// The argument kinds.
const KINDS: [ArgKind; 12] = [
    ArgKind::Message,
    ArgKind::Count,
    ArgKind::Decimal,
    ArgKind::Date,
    ArgKind::Time,
    ArgKind::DateTime,
    ArgKind::Amount,
    ArgKind::Currency,
    ArgKind::Name,
    ArgKind::List,
    ArgKind::Text,
    ArgKind::Raw,
];

const fn kind_byte(kind: ArgKind) -> u8 {
    match kind {
        ArgKind::Message => 0,
        ArgKind::Count => 1,
        ArgKind::Decimal => 2,
        ArgKind::Date => 3,
        ArgKind::Time => 4,
        ArgKind::DateTime => 5,
        ArgKind::Amount => 6,
        ArgKind::Currency => 7,
        ArgKind::Name => 8,
        ArgKind::List => 9,
        ArgKind::Text => 10,
        ArgKind::Raw => 11,
    }
}

/// The styles.
const STYLES: [Style; 3] = [Style::Strong, Style::Emphasis, Style::Underline];

const fn style_byte(style: Style) -> u8 {
    match style {
        Style::Strong => 0,
        Style::Emphasis => 1,
        Style::Underline => 2,
    }
}

/// The `u:dir` values.
const DIRS: [Dir; 4] = [Dir::Inherit, Dir::Ltr, Dir::Rtl, Dir::Auto];

const fn dir_byte(dir: Dir) -> u8 {
    match dir {
        Dir::Inherit => 0,
        Dir::Ltr => 1,
        Dir::Rtl => 2,
        Dir::Auto => 3,
    }
}

/// The presences.
const PRESENCES: [Presence; 2] = [Presence::Required, Presence::Optional];

const fn presence_byte(presence: Presence) -> u8 {
    match presence {
        Presence::Required => 0,
        Presence::Optional => 1,
    }
}

/// The value of `all` whose byte `byte_of` gives is the next byte.
fn by_byte<T: Copy>(
    reader: &mut EntryReader<'_>,
    all: &[T],
    byte_of: fn(T) -> u8,
) -> Result<T, PackageError> {
    let byte = reader.byte()?;
    item(
        reader,
        all.iter().copied().find(|value| byte_of(*value) == byte),
    )
}

/// Writes a style.
pub(super) fn write_style(writer: &mut Writer, style: Style) {
    writer.byte(style_byte(style));
}

/// A style.
pub(super) fn style(reader: &mut EntryReader<'_>) -> Result<Style, PackageError> {
    by_byte(reader, &STYLES, style_byte)
}

/// Writes a compiled call.
fn write_call(writer: &mut Writer, call: &CompiledCall) {
    writer.text(&call.format);
    writer.run(&call.bytes);
}

/// A compiled call.
fn call(reader: &mut EntryReader<'_>) -> Result<CompiledCall, PackageError> {
    Ok(CompiledCall {
        format: text(reader)?,
        bytes: reader.run()?.to_vec(),
    })
}

/// Writes a main module's bare formats: a flag and a call for each kind, in [`BareKind::ALL`]'s
/// order.
#[cfg(feature = "load")]
pub(super) fn write_bare(writer: &mut Writer, bare: &BareCalls) {
    for kind in BareKind::ALL {
        match bare.get(kind) {
            Some(call) => {
                writer.byte(1);
                write_call(writer, call);
            }
            None => writer.byte(0),
        }
    }
}

/// A main module's bare formats.
pub(super) fn bare(reader: &mut EntryReader<'_>) -> Result<BareCalls, PackageError> {
    let mut bare = BareCalls::default();
    for kind in BareKind::ALL {
        match reader.byte()? {
            0 => {}
            1 => bare.set(kind, call(reader)?),
            _ => return Err(reader.malformed()),
        }
    }
    Ok(bare)
}

/// Writes a compiled message.
pub(crate) fn write_message(writer: &mut Writer, message: &MessageForm) {
    writer.text(&message.id);
    write_list(writer, &message.params, |writer, param| {
        writer.text(param.name.as_str());
        writer.byte(kind_byte(param.kind));
        writer.byte(presence_byte(param.presence));
    });
    write_list(writer, &message.expressions, |writer, expression| {
        match &expression.root {
            Root::None => writer.byte(0),
            Root::Literal(literal) => {
                writer.byte(1);
                writer.text(literal);
            }
            Root::Argument(index) => {
                writer.byte(2);
                writer.count(*index);
            }
        }
        write_call(writer, &expression.call);
        writer.byte(dir_byte(expression.dir));
    });
    match &message.body {
        BodyForm::Pattern(parts) => {
            writer.byte(0);
            write_pattern(writer, parts);
        }
        BodyForm::Select {
            selectors,
            variants,
        } => {
            writer.byte(1);
            write_list(writer, selectors, |writer, selector| {
                writer.count(selector.expression);
                write_list(writer, &selector.keys, |writer, key| writer.text(key));
            });
            write_list(writer, variants, |writer, variant| {
                write_list(writer, &variant.keys, |writer, key| match key {
                    KeyRef::CatchAll => writer.count(0),
                    KeyRef::Key(index) => writer.count(index + 1),
                });
                write_pattern(writer, &variant.pattern);
            });
        }
    }
}

/// Writes a pattern.
fn write_pattern(writer: &mut Writer, parts: &[PartForm]) {
    write_list(writer, parts, |writer, part| match part {
        PartForm::Text(text) => {
            writer.byte(0);
            writer.text(text);
        }
        PartForm::Expression(index) => {
            writer.byte(1);
            writer.count(*index);
        }
        PartForm::Open(style) => {
            writer.byte(2);
            write_style(writer, *style);
        }
        PartForm::Close(style) => {
            writer.byte(3);
            write_style(writer, *style);
        }
    });
}

/// A parameter.
fn param(reader: &mut EntryReader<'_>) -> Result<ParamForm, PackageError> {
    let name = DefinedKey::parse(text(reader)?).ok_or(reader.malformed())?;
    let kind = by_byte(reader, &KINDS, kind_byte)?;
    let presence = by_byte(reader, &PRESENCES, presence_byte)?;
    Ok(ParamForm {
        name: ParamName::Defined(name),
        kind,
        presence,
    })
}

/// An expression.
fn expression(reader: &mut EntryReader<'_>) -> Result<Expression, PackageError> {
    let root = match reader.byte()? {
        0 => Root::None,
        1 => Root::Literal(text(reader)?),
        2 => Root::Argument(reader.count()?),
        _ => return Err(reader.malformed()),
    };
    Ok(Expression {
        root,
        call: call(reader)?,
        dir: by_byte(reader, &DIRS, dir_byte)?,
    })
}

/// A compiled message.
pub(super) fn message(reader: &mut EntryReader<'_>) -> Result<MessageForm, PackageError> {
    let id = text(reader)?;
    let params = list(reader, param)?;
    let expressions = list(reader, expression)?;
    let body = match reader.byte()? {
        0 => BodyForm::Pattern(pattern(reader)?),
        1 => {
            let selectors = list(reader, |reader| {
                Ok(SelectorForm {
                    expression: reader.count()?,
                    keys: list(reader, text)?,
                })
            })?;
            let variants = list(reader, |reader| {
                let keys = list(reader, |reader| {
                    Ok(match reader.count()? {
                        0 => KeyRef::CatchAll,
                        key => KeyRef::Key(key - 1),
                    })
                })?;
                Ok(VariantForm {
                    keys,
                    pattern: pattern(reader)?,
                })
            })?;
            BodyForm::Select {
                selectors,
                variants,
            }
        }
        _ => return Err(reader.malformed()),
    };
    Ok(MessageForm {
        id,
        params,
        expressions,
        body,
    })
}

/// A pattern.
fn pattern(reader: &mut EntryReader<'_>) -> Result<Vec<PartForm>, PackageError> {
    list(reader, |reader| {
        Ok(match reader.byte()? {
            0 => PartForm::Text(text(reader)?),
            1 => PartForm::Expression(reader.count()?),
            2 => PartForm::Open(style(reader)?),
            3 => PartForm::Close(style(reader)?),
            _ => return Err(reader.malformed()),
        })
    })
}

/// Writes formatted text: its spans, each its text and its styles.
#[cfg(feature = "load")]
pub(super) fn write_formatted(writer: &mut Writer, formatted: &Formatted) {
    write_list(writer, formatted.spans(), |writer, span| {
        writer.text(span.text());
        write_list(writer, span.styles(), |writer, style| {
            write_style(writer, *style);
        });
    });
}

/// A span as an entry holds it.
struct StoredSpan<'a> {
    text: &'a str,
    styles: Vec<Style>,
}

/// Formatted text, written again through the formatted sink: refused for an empty span, a style
/// given twice in a span, or two adjacent spans with the same styles, which no formatted text
/// holds.
pub(super) fn formatted(reader: &mut EntryReader<'_>) -> Result<Formatted, PackageError> {
    let spans = list(reader, |reader| {
        let text = reader.text()?;
        let styles = list(reader, style)?;
        let repeated = styles
            .iter()
            .enumerate()
            .any(|(index, style)| styles.iter().take(index).any(|earlier| earlier == style));
        if text.is_empty() || repeated {
            return Err(reader.malformed());
        }
        Ok(StoredSpan { text, styles })
    })?;
    let adjacent = spans.windows(2).any(|pair| match pair {
        [a, b] => a.styles == b.styles,
        _ => false,
    });
    if adjacent {
        return Err(reader.malformed());
    }
    let mut sink = FormattedSink::default();
    for span in &spans {
        replay(&mut sink, span.text, &span.styles);
    }
    Ok(sink.finish())
}

/// Writes one span into a sink: its styles opened, its text, its styles closed.
pub(crate) fn replay(sink: &mut dyn Sink, text: &str, styles: &[Style]) {
    for style in styles {
        sink.open(*style);
    }
    sink.text(text);
    for style in styles.iter().rev() {
        sink.close(*style);
    }
}
