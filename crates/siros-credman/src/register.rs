//! The registration writer, which the wallet links: the bytes of the crate README's "Format",
//! written once every request's context loads from them into the same messages with siros-i18n's
//! `nfc` and without it.

use rustc_hash::FxHashSet;
use siros_explain::Explain;
use siros_i18n::{Context, LoadError};
use siros_openid4vp::ids::TransactionType;
use siros_syntax::{Entry, Keyed};

use crate::registration::{Base, COMMA, HEADER, Kind, MAGIC, VERSION, bidi_byte, loaded};

/// A directory entry's bytes beside its name: the kind, the offset, the length and the name's
/// length.
const ENTRY: u32 = 11;

/// Why a registration is not written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum RegisterError {
    /// A base source that holds a name, a variant key or a selector literal Unicode
    /// Normalization Form C changes ([`LoadError::Unnormalized`]).
    #[error("base source {at} holds a name, a key or a selector literal outside NFC")]
    #[explain(id = "register.source")]
    Source {
        /// Its position in load order, from 0.
        at: usize,
        /// The refusal.
        #[source]
        cause: LoadError,
    },
    /// A transaction type's source that `Context::module_in_nfc` refuses in a clone of the base's
    /// context, alone or after the sources of the types before it.
    #[error("the source of the transaction type \"{kind}\" does not load")]
    #[explain(id = "register.transaction")]
    Transaction {
        /// The type.
        kind: TransactionType<'static>,
        /// The refusal.
        #[source]
        cause: LoadError,
    },
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
    for (at, tag) in base.priority().items().iter().enumerate() {
        if at > 0 {
            text.push(COMMA);
        }
        text.push_str(tag.as_str());
    }
    text
}

/// The base's sources loaded again in their order, then each type's source loaded into a clone of
/// that context alone, and every type's source into one clone in ascending order, each through
/// `Context::module_in_nfc`, a source byte-equal to an earlier type's once. A request's context
/// loads the sources of the types it names into a clone of the base's context in that order, so it
/// loads, and a build without siros-i18n's `nfc` loads it into the same messages.
///
/// # Errors
///
/// [`RegisterError::Source`] for the first base source `Context::module_in_nfc` refuses, then
/// [`RegisterError::Transaction`] for the first type's source either context refuses.
fn loads(base: &Base, types: &[&Entry<TransactionType<'_>, String>]) -> Result<(), RegisterError> {
    let context = loaded(
        base.bidi(),
        base.formatters(),
        base.sources(),
        Context::module_in_nfc,
        |at, cause| RegisterError::Source { at, cause },
    )?;
    let mut together = context.clone();
    let mut seen: FxHashSet<&str> = FxHashSet::default();
    for entry in types {
        // Types whose metadata is one object convert to one source, which words its ids once.
        if !seen.insert(entry.value().as_str()) {
            continue;
        }
        let refused = |cause: LoadError| RegisterError::Transaction {
            kind: entry.key().clone().into_owned(),
            cause,
        };
        if let Err(cause) = context.clone().module_in_nfc(entry.value()) {
            return Err(refused(cause));
        }
        together = together.module_in_nfc(entry.value()).map_err(refused)?;
    }
    Ok(())
}

/// The registration of `base` and of each transaction type's converted View source: the
/// header, the directory and the entries, in the directory's order (the crate README's
/// "Format"). Every request's context loads from what it writes, and resolves to the same texts
/// in a build without siros-i18n's `nfc`.
///
/// # Errors
///
/// [`RegisterError::Source`] for a base source with a name, a variant key or a selector literal
/// outside NFC, [`RegisterError::Transaction`] for a type's source that does not load or holds
/// one, [`RegisterError::Name`] for a transaction type past 65,535 bytes,
/// [`RegisterError::Size`] for a registration past 4,294,967,295 bytes, and
/// [`RegisterError::Memory`] for bytes that find no memory.
pub fn write(
    base: &Base,
    transactions: &Keyed<TransactionType<'_>, String>,
) -> Result<Vec<u8>, RegisterError> {
    let mut types: Vec<&Entry<TransactionType<'_>, String>> =
        transactions.entries().iter().collect();
    types.sort_unstable_by(|a, b| a.key().cmp(b.key()));
    loads(base, &types)?;
    let priority = priority(base);
    let bidi = [bidi_byte(base.bidi())];
    let entries = [
        (Kind::Locale, base.locale().as_str().as_bytes()),
        (Kind::Priority, priority.as_bytes()),
        (Kind::Bidi, &bidi[..]),
    ]
    .into_iter()
    .map(|(kind, bytes)| Out::of(kind, "", bytes))
    .chain(
        base.sources()
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
