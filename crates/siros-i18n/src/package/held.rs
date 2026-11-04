//! Precomputed texts: each held under its key, the `Text`'s bytes with the language and the
//! rendering options, with the modules it drew from and its formatted spans.

use sha2::{Digest as _, Sha256};
use siros_explain::{Amount, Date, DateTime, Decimal, Key, ListKind, Offset, Text, Time, Value};

use super::codec::{EntryReader, formatted, list, reader};
#[cfg(feature = "load")]
use super::codec::{write_formatted, write_list};
use super::manifest::StoredId;
use crate::bytes::Writer;
use crate::error::PackageError;
use crate::locale::LocaleTag;
use crate::render::{Amounts, Bidi, OnRenderError, RenderOptions};
use crate::sink::Formatted;

/// What a precomputed text is held under: the text's bytes, the language's tag, and the
/// rendering options, each value in one form, so equal texts have equal keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TextKey(Vec<u8>);

impl TextKey {
    /// The key of `text` in `language` under `options`.
    pub(crate) fn of(text: &Text, language: &LocaleTag, options: RenderOptions) -> Self {
        let mut writer = Writer::default();
        write_text(&mut writer, text);
        writer.text(language.as_str());
        writer.byte(match options.amounts {
            Amounts::Formatted => 0,
            Amounts::Written => 1,
        });
        writer.byte(match options.bidi {
            Bidi::Default => 0,
            Bidi::None => 1,
        });
        writer.byte(match options.on_error {
            OnRenderError::NoEntry => 0,
            OnRenderError::Rendered => 1,
        });
        Self(writer.finish())
    }

    /// Its SHA-256, which the manifest lists.
    pub(crate) fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.0).into()
    }
}

fn write_text(writer: &mut Writer, text: &Text) {
    match text {
        Text::Query(query) => {
            writer.byte(0);
            match query.key() {
                Key::Message(id) => {
                    writer.byte(0);
                    writer.text(id.as_str());
                }
                Key::Defined { module, key } => {
                    writer.byte(1);
                    writer.text(module.plugin().as_str());
                    writer.raw(&module.digest());
                    writer.text(key.as_str());
                }
            }
            writer.count(query.args().len());
            for arg in query.args() {
                writer.text(arg.key());
                write_text(writer, arg.value());
            }
        }
        Text::Value(value) => {
            writer.byte(1);
            write_value(writer, value);
        }
        Text::Name(name) => {
            writer.byte(2);
            writer.text(name);
        }
        Text::List { kind, items } => {
            writer.byte(3);
            writer.byte(match kind {
                ListKind::And => 0,
                ListKind::Or => 1,
            });
            writer.count(items.items().len());
            for item in items.items() {
                write_text(writer, item);
            }
        }
        Text::Absent => writer.byte(4),
        Text::Raw(raw) => {
            writer.byte(5);
            writer.text(raw);
        }
    }
}

fn write_decimal(writer: &mut Writer, decimal: Decimal) {
    writer.raw(&decimal.units().to_be_bytes());
    writer.byte(decimal.scale());
}

fn write_date(writer: &mut Writer, date: Date) {
    writer.number(u64::from(date.year()));
    writer.byte(date.month());
    writer.byte(date.day());
}

fn write_time(writer: &mut Writer, time: Time) {
    writer.byte(time.hour());
    writer.byte(time.minute());
    match time.second() {
        Some(second) => {
            writer.byte(1);
            writer.byte(second.whole());
            writer.number(u64::from(second.fraction().nanos()));
            writer.byte(second.fraction().digits());
        }
        None => writer.byte(0),
    }
}

fn write_offset(writer: &mut Writer, offset: Option<Offset>) {
    match offset {
        Some(offset) => {
            writer.byte(1);
            writer.raw(&offset.minutes().to_be_bytes());
        }
        None => writer.byte(0),
    }
}

fn write_date_time(writer: &mut Writer, value: DateTime) {
    write_date(writer, value.date());
    writer.byte(value.hour());
    writer.byte(value.minute());
    match value.second() {
        Some(second) => {
            writer.byte(1);
            writer.byte(second);
        }
        None => writer.byte(0),
    }
    writer.number(u64::from(value.fraction().nanos()));
    writer.byte(value.fraction().digits());
    write_offset(writer, value.offset());
}

fn write_amount(writer: &mut Writer, amount: Amount) {
    write_decimal(writer, amount.value());
    writer.raw(&amount.currency().code());
}

fn write_value(writer: &mut Writer, value: &Value) {
    match value {
        Value::Count(count) => {
            writer.byte(0);
            writer.text(&count.digits());
        }
        Value::Decimal(decimal) => {
            writer.byte(1);
            write_decimal(writer, *decimal);
        }
        Value::Date(date) => {
            writer.byte(2);
            write_date(writer, *date);
        }
        Value::Time { at, offset } => {
            writer.byte(3);
            write_time(writer, *at);
            write_offset(writer, *offset);
        }
        Value::DateTime(date_time) => {
            writer.byte(4);
            write_date_time(writer, *date_time);
        }
        Value::Amount(amount) => {
            writer.byte(5);
            write_amount(writer, *amount);
        }
        Value::Currency(currency) => {
            writer.byte(6);
            writer.raw(&currency.code());
        }
    }
}

/// A precomputed text: its key, the modules its rendering drew from, and its spans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Held {
    pub(crate) key: TextKey,
    pub(crate) reached: Vec<StoredId>,
    pub(crate) formatted: Formatted,
}

impl Held {
    /// Held entry `index`.
    pub(crate) fn decode(bytes: &[u8], index: usize) -> Result<Self, PackageError> {
        let mut reader = reader(bytes, index);
        let reader: &mut EntryReader<'_> = &mut reader;
        let key = TextKey(reader.run()?.to_vec());
        let reached = list(reader, StoredId::decode)?;
        let formatted = formatted(reader)?;
        if !reader.is_empty() {
            return Err(reader.malformed());
        }
        Ok(Self {
            key,
            reached,
            formatted,
        })
    }

    /// The held entry's bytes.
    #[cfg(feature = "load")]
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.run(&self.key.0);
        write_list(&mut writer, &self.reached, |writer, id| {
            writer.raw(id.encoded());
        });
        write_formatted(&mut writer, &self.formatted);
        writer.finish()
    }
}
