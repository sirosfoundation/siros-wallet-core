//! The registration writer, which the wallet links: the bytes of the crate README's "Format".

use siros_explain::Explain;
use siros_openid4vp::ids::TransactionType;
use siros_syntax::{Entry, Keyed};

use crate::registration::{Base, COMMA, HEADER, Kind, MAGIC, VERSION, bidi_byte};

/// A directory entry's bytes beside its name: the kind, the offset, the length and the name's
/// length.
const ENTRY: u32 = 11;

/// Why a registration is not written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum RegisterError {
    /// A transaction type longer than a name holds.
    #[error("a transaction type of {length} bytes passes the 65535 a name holds")]
    #[explain(id = "register.name")]
    Name {
        /// The type's bytes.
        length: usize,
    },
    /// More bytes than a u32 offset reaches.
    #[error("the registration passes the 4294967295 bytes a registration holds")]
    #[explain(id = "register.size")]
    Size,
    /// The registration's bytes find no memory.
    #[error("the registration's {size} bytes find no memory")]
    #[explain(id = "register.memory")]
    Memory {
        /// The bytes.
        size: u32,
    },
}

/// An entry as the directory lists it.
struct Out<'w> {
    kind: Kind,
    name: &'w str,
    name_length: u16,
    bytes: &'w [u8],
    length: u32,
}

impl<'w> Out<'w> {
    /// The entry of `kind` named `name` holding `bytes`.
    ///
    /// # Errors
    ///
    /// [`RegisterError::Name`] for a name past 65,535 bytes, and [`RegisterError::Size`] for
    /// bytes past 4,294,967,295.
    fn of(kind: Kind, name: &'w str, bytes: &'w [u8]) -> Result<Self, RegisterError> {
        Ok(Self {
            kind,
            name,
            name_length: u16::try_from(name.len())
                .map_err(|_| RegisterError::Name { length: name.len() })?,
            bytes,
            length: u32::try_from(bytes.len()).map_err(|_| RegisterError::Size)?,
        })
    }

    /// Its directory entry's bytes.
    fn listed(&self) -> u32 {
        ENTRY + u32::from(self.name_length)
    }
}

/// The priority entry's text: the tags in their order, a comma after each but the last.
fn priority(base: &Base) -> String {
    let mut text = String::new();
    for (at, tag) in base.priority.items().iter().enumerate() {
        if at > 0 {
            text.push(COMMA);
        }
        text.push_str(tag.as_str());
    }
    text
}

/// The registration of `base` and of each transaction type's converted View source: the
/// header, the directory and the entries, in the directory's order (the crate README's
/// "Format").
///
/// # Errors
///
/// [`RegisterError::Name`] for a transaction type past 65,535 bytes,
/// [`RegisterError::Size`] for a registration past 4,294,967,295 bytes, and
/// [`RegisterError::Memory`] for bytes that find no memory.
pub fn write(
    base: &Base,
    transactions: &Keyed<TransactionType<'_>, String>,
) -> Result<Vec<u8>, RegisterError> {
    let priority = priority(base);
    let bidi = [bidi_byte(base.bidi)];
    let on_error = [base.on_error.byte()];
    let mut types: Vec<&Entry<TransactionType<'_>, String>> =
        transactions.entries().iter().collect();
    types.sort_unstable_by(|a, b| a.key().cmp(b.key()));
    let entries = [
        (Kind::Locale, base.locale.as_str().as_bytes()),
        (Kind::Priority, priority.as_bytes()),
        (Kind::Bidi, &bidi[..]),
        (Kind::OnError, &on_error[..]),
    ]
    .into_iter()
    .map(|(kind, bytes)| Out::of(kind, "", bytes))
    .chain(
        base.sources
            .items()
            .iter()
            .map(|source| Out::of(Kind::Source, "", source.as_bytes())),
    )
    .chain(types.iter().map(|entry| {
        Out::of(
            Kind::Transaction,
            entry.key().as_str(),
            entry.value().as_bytes(),
        )
    }))
    .collect::<Result<Vec<Out<'_>>, RegisterError>>()?;
    let directory = entries
        .iter()
        .try_fold(0_u32, |sum, out| sum.checked_add(out.listed()))
        .ok_or(RegisterError::Size)?;
    let start = HEADER.checked_add(directory).ok_or(RegisterError::Size)?;
    let size = entries
        .iter()
        .try_fold(start, |end, out| end.checked_add(out.length))
        .ok_or(RegisterError::Size)?;
    let memory = RegisterError::Memory { size };
    let Ok(count) = usize::try_from(size) else {
        return Err(memory);
    };
    let mut blob = Vec::new();
    if blob.try_reserve_exact(count).is_err() {
        return Err(memory);
    }
    blob.extend_from_slice(&MAGIC);
    blob.extend_from_slice(&VERSION.to_le_bytes());
    blob.extend_from_slice(&directory.to_le_bytes());
    let mut offset = start;
    for out in &entries {
        blob.push(out.kind.code());
        blob.extend_from_slice(&offset.to_le_bytes());
        blob.extend_from_slice(&out.length.to_le_bytes());
        blob.extend_from_slice(&out.name_length.to_le_bytes());
        blob.extend_from_slice(out.name.as_bytes());
        // The entries end at `size`, a u32.
        offset += out.length;
    }
    for out in &entries {
        blob.extend_from_slice(out.bytes);
    }
    Ok(blob)
}
