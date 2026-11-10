//! The matcher's reader of a registration (the crate README's "Format"). Opening one reads the
//! header, the directory, every span checked against the blob's size, and the base entries, and
//! loads the base's context; a transaction type's source is read when a request names the type.

use std::io::{self, Read, Seek, SeekFrom};
use std::marker::PhantomData;

use rustc_hash::FxHashSet;
use siros_explain::Explain;
use siros_i18n::{Bidi, Context, LocaleTag};
use siros_openid4vp::ids::TransactionType;
use siros_openid4vp::request::{Entry, Request};
use siros_syntax::AllOf;

use crate::registration::{
    Base, COMMA, ContextError, HEADER, Kind, MAGIC, VERSION, bidi_of, canonical_tag,
};

/// A rule of the format a registration breaks (the crate README's "Format"). An `entry` is a
/// directory entry's position, from 0.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum Malformed {
    /// The blob holds more bytes than a u32 offset reaches.
    #[error("the registration's {size} bytes pass the 4294967295 a registration holds")]
    #[explain(id = "malformed.size")]
    Size {
        /// The blob's bytes.
        size: u64,
    },
    /// The blob ends inside the header.
    #[error("the registration's {size} bytes end inside its header")]
    #[explain(id = "malformed.header")]
    Header {
        /// The blob's bytes.
        size: u32,
    },
    /// The blob starts with other bytes than the magic.
    #[error("the registration starts with other bytes than its magic")]
    #[explain(id = "malformed.magic")]
    Magic,
    /// A version of the format this crate does not read.
    #[error("the registration's format version {version} is unknown")]
    #[explain(id = "malformed.version")]
    Version {
        /// The header's version.
        version: u32,
    },
    /// The directory ends past the blob.
    #[error("the directory's {length} bytes end past the registration's {size}")]
    #[explain(id = "malformed.directory")]
    Directory {
        /// The directory's bytes, as the header states them.
        length: u32,
        /// The blob's bytes.
        size: u32,
    },
    /// The directory ends inside an entry.
    #[error("the directory ends inside entry {entry}")]
    #[explain(id = "malformed.entry")]
    Entry {
        /// The entry.
        entry: usize,
    },
    /// A kind code the version does not define.
    #[error("entry {entry} has the unknown kind {code}")]
    #[explain(id = "malformed.kind")]
    Kind {
        /// The entry.
        entry: usize,
        /// Its kind code.
        code: u8,
    },
    /// A name that is no UTF-8 text.
    #[error("the name of entry {entry} is no UTF-8 text")]
    #[explain(id = "malformed.name")]
    Name {
        /// The entry.
        entry: usize,
    },
    /// A name on an entry of a kind that takes none.
    #[error("entry {entry}, of kind {kind}, has a name")]
    #[explain(id = "malformed.named")]
    Named {
        /// The entry.
        entry: usize,
        /// Its kind.
        kind: Kind,
    },
    /// An entry that ends past the blob.
    #[error("entry {entry}, {length} bytes at {offset}, ends past the registration's {size}")]
    #[explain(id = "malformed.span")]
    Span {
        /// The entry.
        entry: usize,
        /// Its offset.
        offset: u32,
        /// Its length.
        length: u32,
        /// The blob's bytes.
        size: u32,
    },
    /// An entry that starts elsewhere than where the bytes before it end: the previous entry, or
    /// the directory for the first entry.
    #[error("entry {entry} starts at {offset}, where the bytes before it end at {end}")]
    #[explain(id = "malformed.tiling")]
    Tiling {
        /// The entry.
        entry: usize,
        /// Its offset.
        offset: u32,
        /// Where the bytes before it end.
        end: u32,
    },
    /// Bytes after the last entry.
    #[error("the entries end at {end}, before the registration's {size} bytes")]
    #[explain(id = "malformed.trailing")]
    Trailing {
        /// Where the entries end.
        end: u32,
        /// The blob's bytes.
        size: u32,
    },
    /// An entry that comes before the previous one in the directory's order.
    #[error("entry {entry} comes before the previous entry in the directory's order")]
    #[explain(id = "malformed.order")]
    Order {
        /// The entry.
        entry: usize,
    },
    /// A second entry of a kind the directory lists once, or of a transaction type.
    #[error("entry {entry} repeats an entry of kind {kind}")]
    #[explain(id = "malformed.repeated")]
    Repeated {
        /// The entry.
        entry: usize,
        /// Its kind.
        kind: Kind,
    },
    /// No entry of a kind the directory lists at least once.
    #[error("the directory lists no entry of kind {kind}")]
    #[explain(id = "malformed.missing")]
    Missing {
        /// The kind.
        kind: Kind,
    },
    /// A locale entry that is no language tag in its canonical form.
    #[error("entry {entry}, the locale, is no language tag in its canonical form")]
    #[explain(id = "malformed.locale")]
    Locale {
        /// The entry.
        entry: usize,
    },
    /// A priority entry that is no list of language tags in their canonical form, each followed
    /// by a comma but the last.
    #[error("entry {entry}, the priority list, is no list of language tags in canonical form")]
    #[explain(id = "malformed.priority")]
    Priority {
        /// The entry.
        entry: usize,
    },
    /// A bidi entry other than the byte 0 or 1.
    #[error("entry {entry}, the bidi choice, is not the byte 0 or 1")]
    #[explain(id = "malformed.bidi")]
    Bidi {
        /// The entry.
        entry: usize,
    },
    /// A source or a transaction type's source that is no UTF-8 text.
    #[error("entry {entry}, a source, is no UTF-8 text")]
    #[explain(id = "malformed.text")]
    Text {
        /// The entry.
        entry: usize,
    },
}

/// Why a registration does not read.
#[derive(Debug, thiserror::Error, Explain)]
pub enum ReadError {
    /// The reader fails.
    #[error("the registration's reader fails")]
    #[explain(id = "read.io")]
    Io {
        /// The failure.
        #[from]
        cause: io::Error,
    },
    /// The reader seeks elsewhere than asked.
    #[error("the registration's reader seeks to {at} when asked for {offset}")]
    #[explain(id = "read.seek")]
    Seek {
        /// The position asked for.
        offset: u64,
        /// The position the reader reports.
        at: u64,
    },
    /// The bytes of an entry or of the directory find no memory.
    #[error("{length} bytes of the registration find no memory")]
    #[explain(id = "read.memory")]
    Memory {
        /// The bytes.
        length: u32,
    },
    /// The registration breaks a rule of its format.
    #[error(transparent)]
    Malformed(#[from] Malformed),
    /// The registration's sources do not load into the matcher's context.
    #[error(transparent)]
    Context(#[from] ContextError),
}

/// An entry's kind as a type: what a [`Span`] holds, and how its bytes decode.
trait Part {
    /// What the entry holds.
    type Value;

    /// The bytes of the entry at position `entry` decoded.
    fn decode(bytes: Vec<u8>, entry: usize) -> Result<Self::Value, Malformed>;
}

/// The locale entry.
#[derive(Debug)]
enum LocalePart {}

/// The priority entry.
#[derive(Debug)]
enum PriorityPart {}

/// The bidi entry.
#[derive(Debug)]
enum BidiPart {}

/// A source entry.
#[derive(Debug)]
enum SourcePart {}

/// A transaction entry.
#[derive(Debug)]
enum TransactionPart {}

impl Part for LocalePart {
    type Value = LocaleTag;

    fn decode(bytes: Vec<u8>, entry: usize) -> Result<LocaleTag, Malformed> {
        std::str::from_utf8(&bytes)
            .ok()
            .and_then(canonical_tag)
            .ok_or(Malformed::Locale { entry })
    }
}

impl Part for PriorityPart {
    type Value = AllOf<LocaleTag>;

    fn decode(bytes: Vec<u8>, entry: usize) -> Result<AllOf<LocaleTag>, Malformed> {
        std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| text.split(COMMA).map(canonical_tag).collect())
            .and_then(AllOf::new)
            .ok_or(Malformed::Priority { entry })
    }
}

impl Part for BidiPart {
    type Value = Bidi;

    fn decode(bytes: Vec<u8>, entry: usize) -> Result<Bidi, Malformed> {
        match bytes.as_slice() {
            [byte] => bidi_of(*byte),
            _ => None,
        }
        .ok_or(Malformed::Bidi { entry })
    }
}

impl Part for SourcePart {
    type Value = String;

    fn decode(bytes: Vec<u8>, entry: usize) -> Result<String, Malformed> {
        text(bytes, entry)
    }
}

impl Part for TransactionPart {
    type Value = String;

    fn decode(bytes: Vec<u8>, entry: usize) -> Result<String, Malformed> {
        text(bytes, entry)
    }
}

/// The text of a source entry's bytes.
fn text(bytes: Vec<u8>, entry: usize) -> Result<String, Malformed> {
    String::from_utf8(bytes).map_err(|_| Malformed::Text { entry })
}

/// The bytes of the entry at position `entry` in the blob, an entry of the kind `P`. Only
/// [`Bounds::span`] makes one, and the bounds end within the blob.
#[derive(Debug)]
struct Span<P> {
    entry: usize,
    offset: u32,
    length: u32,
    part: PhantomData<fn() -> P>,
}

// Derived impls would bound `P`, a type without values.
impl<P> Clone for Span<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P> Copy for Span<P> {}

/// An entry's offset and length, which end within the blob.
#[derive(Debug, Clone, Copy)]
struct Bounds {
    entry: usize,
    offset: u32,
    length: u32,
    end: u32,
}

impl Bounds {
    /// The `length` bytes at `offset` of the entry at position `entry`.
    ///
    /// # Errors
    ///
    /// [`Malformed::Span`] for bytes that end past the blob's `size`.
    fn within(entry: usize, offset: u32, length: u32, size: u32) -> Result<Self, Malformed> {
        offset
            .checked_add(length)
            .filter(|end| *end <= size)
            .map(|end| Self {
                entry,
                offset,
                length,
                end,
            })
            .ok_or(Malformed::Span {
                entry,
                offset,
                length,
                size,
            })
    }

    /// The bounds as the span of an entry of kind `P`.
    const fn span<P>(self) -> Span<P> {
        Span {
            entry: self.entry,
            offset: self.offset,
            length: self.length,
            part: PhantomData,
        }
    }
}

/// The directory's bytes not yet read.
struct Cursor<'b>(&'b [u8]);

impl<'b> Cursor<'b> {
    /// The next `N` bytes.
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*head)
    }

    /// The next `length` bytes.
    fn bytes(&mut self, length: usize) -> Option<&'b [u8]> {
        let (head, rest) = self.0.split_at_checked(length)?;
        self.0 = rest;
        Some(head)
    }

    /// The next directory entry, as written.
    fn entry(&mut self) -> Option<Written<'b>> {
        let [code] = self.array::<1>()?;
        let offset = u32::from_le_bytes(self.array::<4>()?);
        let length = u32::from_le_bytes(self.array::<4>()?);
        let name = usize::from(u16::from_le_bytes(self.array::<2>()?));
        Some(Written {
            code,
            offset,
            length,
            name: self.bytes(name)?,
        })
    }
}

/// A directory entry as written, before its rules are checked.
struct Written<'b> {
    code: u8,
    offset: u32,
    length: u32,
    name: &'b [u8],
}

/// A registered transaction type and its source.
#[derive(Debug)]
struct Registered {
    kind: TransactionType<'static>,
    span: Span<TransactionPart>,
}

/// The entries the directory lists so far.
#[derive(Debug, Default)]
struct Found {
    locale: Option<Span<LocalePart>>,
    priority: Option<Span<PriorityPart>>,
    bidi: Option<Span<BidiPart>>,
    sources: Vec<Span<SourcePart>>,
    transactions: Vec<Registered>,
}

/// The directory: the base entries' spans by kind and the registered transaction types, ascending.
#[derive(Debug)]
struct Directory {
    locale: Span<LocalePart>,
    priority: Span<PriorityPart>,
    bidi: Span<BidiPart>,
    sources: AllOf<Span<SourcePart>>,
    transactions: Vec<Registered>,
}

/// The span in its slot, which holds none yet.
fn once<P>(slot: &mut Option<Span<P>>, bounds: Bounds, kind: Kind) -> Result<(), Malformed> {
    match slot {
        Some(_) => Err(Malformed::Repeated {
            entry: bounds.entry,
            kind,
        }),
        None => {
            *slot = Some(bounds.span());
            Ok(())
        }
    }
}

impl Found {
    /// The entry of `kind` named `name` at `bounds`, listed after the entries found.
    ///
    /// # Errors
    ///
    /// [`Malformed::Repeated`] for a second entry of a kind listed once or of a transaction type,
    /// [`Malformed::Order`] for a transaction type before the previous one, and
    /// [`Malformed::Name`] for a name that is no transaction type.
    fn add(&mut self, kind: Kind, name: &str, bounds: Bounds) -> Result<(), Malformed> {
        let entry = bounds.entry;
        match kind {
            Kind::Locale => once(&mut self.locale, bounds, kind),
            Kind::Priority => once(&mut self.priority, bounds, kind),
            Kind::Bidi => once(&mut self.bidi, bounds, kind),
            Kind::Source => {
                self.sources.push(bounds.span());
                Ok(())
            }
            Kind::Transaction => {
                if let Some(last) = self.transactions.last() {
                    match name.cmp(last.kind.as_str()) {
                        std::cmp::Ordering::Less => return Err(Malformed::Order { entry }),
                        std::cmp::Ordering::Equal => {
                            return Err(Malformed::Repeated { entry, kind });
                        }
                        std::cmp::Ordering::Greater => {}
                    }
                }
                let registered = TransactionType::parse(name.to_owned())
                    .map_err(|_| Malformed::Name { entry })?;
                self.transactions.push(Registered {
                    kind: registered,
                    span: bounds.span(),
                });
                Ok(())
            }
        }
    }

    /// The directory, once every kind it lists at least once is found.
    ///
    /// # Errors
    ///
    /// [`Malformed::Missing`] for the first kind, in code order, without an entry.
    fn directory(self) -> Result<Directory, Malformed> {
        Ok(Directory {
            locale: self
                .locale
                .ok_or(Malformed::Missing { kind: Kind::Locale })?,
            priority: self.priority.ok_or(Malformed::Missing {
                kind: Kind::Priority,
            })?,
            bidi: self.bidi.ok_or(Malformed::Missing { kind: Kind::Bidi })?,
            sources: AllOf::new(self.sources).ok_or(Malformed::Missing { kind: Kind::Source })?,
            transactions: self.transactions,
        })
    }
}

impl Directory {
    /// The directory `bytes` of a blob of `size` bytes, whose first entry starts at `start`,
    /// where the directory ends.
    ///
    /// # Errors
    ///
    /// The [`Malformed`] of the first rule an entry breaks, in the order of the crate README's
    /// "Format"; then [`Malformed::Trailing`] and [`Malformed::Missing`].
    fn parse(bytes: &[u8], start: u32, size: u32) -> Result<Self, Malformed> {
        let mut cursor = Cursor(bytes);
        let mut found = Found::default();
        let mut end = start;
        let mut previous: Option<Kind> = None;
        for entry in 0.. {
            if cursor.0.is_empty() {
                break;
            }
            let written = cursor.entry().ok_or(Malformed::Entry { entry })?;
            let kind = Kind::of(written.code).ok_or(Malformed::Kind {
                entry,
                code: written.code,
            })?;
            let name = std::str::from_utf8(written.name).map_err(|_| Malformed::Name { entry })?;
            if kind != Kind::Transaction && !name.is_empty() {
                return Err(Malformed::Named { entry, kind });
            }
            let bounds = Bounds::within(entry, written.offset, written.length, size)?;
            if bounds.offset != end {
                return Err(Malformed::Tiling {
                    entry,
                    offset: bounds.offset,
                    end,
                });
            }
            if previous.is_some_and(|previous| kind < previous) {
                return Err(Malformed::Order { entry });
            }
            found.add(kind, name, bounds)?;
            end = bounds.end;
            previous = Some(kind);
        }
        if end != size {
            return Err(Malformed::Trailing { end, size });
        }
        found.directory()
    }
}

/// Moves `reader` to `offset`.
///
/// # Errors
///
/// [`ReadError::Io`] for a failing reader, and [`ReadError::Seek`] for one that moves elsewhere.
fn seek<R: Seek>(reader: &mut R, offset: u32) -> Result<(), ReadError> {
    let offset = u64::from(offset);
    let at = reader.seek(SeekFrom::Start(offset))?;
    if at == offset {
        Ok(())
    } else {
        Err(ReadError::Seek { offset, at })
    }
}

/// The `length` bytes at `offset`.
///
/// # Errors
///
/// [`ReadError::Memory`] for bytes that find no memory, and the reader's failure.
fn bytes_at<R: Read + Seek>(
    reader: &mut R,
    offset: u32,
    length: u32,
) -> Result<Vec<u8>, ReadError> {
    let memory = ReadError::Memory { length };
    let Ok(count) = usize::try_from(length) else {
        return Err(memory);
    };
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(count).is_err() {
        return Err(memory);
    }
    bytes.resize(count, 0);
    seek(reader, offset)?;
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// The value of the entry at `span`.
///
/// # Errors
///
/// The reader's failure, and the [`Malformed`] of an entry its kind does not decode.
fn read<R: Read + Seek, P: Part>(reader: &mut R, span: Span<P>) -> Result<P::Value, ReadError> {
    let bytes = bytes_at(reader, span.offset, span.length)?;
    Ok(P::decode(bytes, span.entry)?)
}

/// A registration in a reader: its header, directory and base entries read, and its base's
/// context loaded.
#[derive(Debug)]
pub struct Registration<R> {
    reader: R,
    base: Base,
    transactions: Vec<Registered>,
}

impl<R> Registration<R> {
    /// The base entries, which every request reads, and their context.
    #[must_use]
    pub const fn base(&self) -> &Base {
        &self.base
    }

    /// The registered transaction types, ascending by their UTF-8 bytes.
    pub fn transactions(&self) -> impl ExactSizeIterator<Item = &TransactionType<'static>> {
        self.transactions.iter().map(|registered| &registered.kind)
    }

    /// The span of `kind`'s source; `None` for a type the registration does not register.
    fn find(&self, kind: &TransactionType<'_>) -> Option<Span<TransactionPart>> {
        let at = self
            .transactions
            .partition_point(|registered| registered.kind.as_str() < kind.as_str());
        self.transactions
            .get(at)
            .filter(|registered| registered.kind.as_str() == kind.as_str())
            .map(|registered| registered.span)
    }
}

impl<R: Read + Seek> Registration<R> {
    /// The registration `reader` holds from its start to its end: the header, the directory and
    /// the base entries read, the base's sources loaded ([`Base::load`]), and every rule of the
    /// crate README's "Format" checked but those of a transaction source, which
    /// [`Registration::transaction`] and [`Registration::context`] check.
    ///
    /// # Errors
    ///
    /// [`ReadError::Malformed`] for the first rule the registration breaks,
    /// [`ReadError::Context`] for base sources that do not load, and the reader's failure.
    pub fn open(mut reader: R) -> Result<Self, ReadError> {
        let size = reader.seek(SeekFrom::End(0))?;
        let size = u32::try_from(size).map_err(|_| Malformed::Size { size })?;
        if size < HEADER {
            return Err(Malformed::Header { size }.into());
        }
        seek(&mut reader, 0)?;
        let mut header = [0; HEADER as usize];
        reader.read_exact(&mut header)?;
        let [magic @ .., v0, v1, v2, v3, d0, d1, d2, d3] = header;
        if magic != MAGIC {
            return Err(Malformed::Magic.into());
        }
        let version = u32::from_le_bytes([v0, v1, v2, v3]);
        if version != VERSION {
            return Err(Malformed::Version { version }.into());
        }
        let length = u32::from_le_bytes([d0, d1, d2, d3]);
        let start = HEADER
            .checked_add(length)
            .filter(|end| *end <= size)
            .ok_or(Malformed::Directory { length, size })?;
        let bytes = bytes_at(&mut reader, HEADER, length)?;
        let directory = Directory::parse(&bytes, start, size)?;
        let base = Base::load(
            read(&mut reader, directory.locale)?,
            read(&mut reader, directory.priority)?,
            read(&mut reader, directory.bidi)?,
            directory.sources.try_map(|span| read(&mut reader, *span))?,
        )?;
        Ok(Self {
            reader,
            base,
            transactions: directory.transactions,
        })
    }

    /// The converted View source of the transaction type `kind`; `None` for a type the
    /// registration does not register.
    ///
    /// # Errors
    ///
    /// [`Malformed::Text`] for a source that is no UTF-8 text, and the reader's failure.
    pub fn transaction(&mut self, kind: &TransactionType<'_>) -> Result<Option<String>, ReadError> {
        self.find(kind)
            .map(|span| read(&mut self.reader, span))
            .transpose()
    }

    /// The matcher's context for `request`: a clone of [`Base::context`] that loads the source of
    /// each registered type the request's `transaction_data` names, ascending by type, a source
    /// byte-equal to one it loaded once. It reads no other entry. A type the registration does
    /// not register loads nothing: its profile converts the metadata the request carries.
    ///
    /// # Errors
    ///
    /// [`ReadError::Context`] for a source the context refuses, [`Malformed::Text`] for a source
    /// that is no UTF-8 text, and the reader's failure.
    pub fn context(&mut self, request: &Request<'_>) -> Result<Context, ReadError> {
        let mut kinds: Vec<&TransactionType<'static>> =
            request.entries().iter().map(Entry::kind).collect();
        kinds.sort_unstable();
        kinds.dedup();
        let mut context = self.base.context().clone();
        let mut loaded: FxHashSet<String> = FxHashSet::default();
        for kind in kinds {
            let Some(source) = self.transaction(kind)? else {
                continue;
            };
            // Types whose metadata is one object convert to one source, which words its ids once.
            if loaded.contains(&source) {
                continue;
            }
            context = context
                .module(&source)
                .map_err(|cause| ContextError::Transaction {
                    kind: kind.clone(),
                    cause,
                })?;
            loaded.extend([source]);
        }
        Ok(context)
    }
}
