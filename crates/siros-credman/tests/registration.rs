//! The registration's format, as the crate README's "Format" lays it out: the writer writes that
//! layout and the reader gives back what was written; a registration that breaks a rule is
//! refused with that rule's error; a request reads the header, the directory, the base entries
//! and the source of the transaction type it names, and no other byte.

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use siros_credman::register::{RegisterError, write};
use siros_credman::{Base, ContextError, Kind, Malformed, OnRenderError, ReadError, Registration};
use siros_i18n::{Bidi, Context, LoadError, LocaleTag, ResolveError};
use siros_openid4vp::ids::TransactionType;
use siros_openid4vp::request::Request;
use siros_syntax::{AllOf, Entry, Keyed};
use siros_testkit::fixtures::{parameters, request_of, unsigned};
use siros_testkit::render::Language;
use siros_testkit::verifier::encode;

const QUERY: &str = r#"{"credentials":[{"id":"q","format":"test"}]}"#;

/// A source that loads into an English context and words nothing.
const SOURCE: &str = "@locale en\n---\n";

/// A record of the directory and its entry's bytes.
struct Record {
    code: u8,
    name: Vec<u8>,
    bytes: Vec<u8>,
}

fn record(code: u8, bytes: &[u8]) -> Record {
    named(code, b"", bytes)
}

fn named(code: u8, name: &[u8], bytes: &[u8]) -> Record {
    Record {
        code,
        name: name.to_vec(),
        bytes: bytes.to_vec(),
    }
}

/// The README's layout of `records`, with `tail` after the last record inside the directory: the
/// header, the directory, then the entries back to back.
fn laid_out(records: &[Record], tail: &[u8]) -> Vec<u8> {
    let directory = records.iter().map(|r| 11 + r.name.len()).sum::<usize>() + tail.len();
    let mut blob = vec![0x89, 0x53, 0x43, 0x4D, 0x0D, 0x0A, 0x1A, 0x0A];
    blob.extend(1_u32.to_le_bytes());
    blob.extend(u32::try_from(directory).expect("a u32").to_le_bytes());
    let mut offset = 16 + directory;
    for r in records {
        blob.push(r.code);
        blob.extend(u32::try_from(offset).expect("a u32").to_le_bytes());
        blob.extend(u32::try_from(r.bytes.len()).expect("a u32").to_le_bytes());
        blob.extend(u16::try_from(r.name.len()).expect("a u16").to_le_bytes());
        blob.extend(&r.name);
        offset += r.bytes.len();
    }
    blob.extend(tail);
    for r in records {
        blob.extend(&r.bytes);
    }
    blob
}

/// Where record `entry` starts in the layout of `records`.
fn start_of(records: &[Record], entry: usize) -> usize {
    16 + records[..entry]
        .iter()
        .map(|r| 11 + r.name.len())
        .sum::<usize>()
}

/// The u32 at `offset` of `blob`.
fn u32_at(blob: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(blob[offset..offset + 4].try_into().expect("four bytes"))
}

fn tag(text: &str) -> LocaleTag {
    LocaleTag::parse(text).expect("a tag")
}

fn kind(text: &str) -> TransactionType<'static> {
    TransactionType::parse(text.to_owned()).expect("a type")
}

/// The records of a registration that keeps every rule: locale `en`, priority `en,de-CH`, the
/// Default Bidi Strategy, the entries that resolved, one source and the type `t1`.
fn honest() -> Vec<Record> {
    vec![
        record(1, b"en"),
        record(2, b"en,de-CH"),
        record(3, &[0]),
        record(4, &[1]),
        record(5, SOURCE.as_bytes()),
        named(6, b"t1", SOURCE.as_bytes()),
    ]
}

/// What the honest records hold.
fn honest_base() -> Base {
    Base {
        locale: tag("en"),
        priority: AllOf::new(vec![tag("en"), tag("de-CH")]).expect("tags"),
        bidi: Bidi::Default,
        on_error: OnRenderError::Rendered,
        sources: AllOf::one(SOURCE.to_owned()),
    }
}

/// The request whose `transaction_data` names `kinds`.
fn request_naming(kinds: &[&str]) -> String {
    let entries: Vec<String> = kinds
        .iter()
        .map(|kind| {
            let entry = format!(r#"{{"type":"{kind}","credential_ids":["q"]}}"#);
            format!("\"{}\"", encode(&entry).expect("an entry"))
        })
        .collect();
    parameters(
        QUERY,
        &format!(r#""transaction_data":[{}]"#, entries.join(",")),
    )
}

/// The writer writes the README's layout, and the reader gives back each entry written: the
/// base, and every transaction type's source, the types listed ascending.
#[test]
fn the_reader_gives_back_what_the_writer_writes() {
    let transactions = Keyed::new(vec![Entry::new(kind("t1"), SOURCE.to_owned())]).expect("types");
    assert_eq!(
        write(&honest_base(), &transactions).expect("written"),
        laid_out(&honest(), &[]),
        "the writer writes the README's layout"
    );
    let bases = [
        honest_base(),
        Base {
            locale: tag("zh-Hant-TW"),
            priority: AllOf::new(vec![tag("zh-Hant-TW"), tag("en"), tag("de-CH-x-phonebk")])
                .expect("tags"),
            bidi: Bidi::None,
            on_error: OnRenderError::NoEntry,
            sources: AllOf::new(vec![
                "first".to_owned(),
                String::new(),
                "third, \u{2068}بالعربية\u{2069}".to_owned(),
            ])
            .expect("sources"),
        },
    ];
    // Given out of order: the directory lists them ascending by their UTF-8 bytes.
    let given = [
        ("urn:example:payment", "a payment"),
        ("", "the empty type"),
        ("Ünicode", "a type past ASCII"),
        ("t1", "t1's source"),
    ];
    let transactions = Keyed::new(
        given
            .iter()
            .map(|(name, source)| Entry::new(kind(name), (*source).to_owned()))
            .collect(),
    )
    .expect("distinct types");
    let mut ascending: Vec<&str> = given.iter().map(|(name, _)| *name).collect();
    ascending.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    for base in bases {
        let blob = write(&base, &transactions).expect("written");
        let mut registration = Registration::open(Cursor::new(blob)).expect("opened");
        assert_eq!(registration.base(), &base);
        let listed: Vec<&str> = registration
            .transactions()
            .map(TransactionType::as_str)
            .collect();
        assert_eq!(listed, ascending);
        for (name, source) in given {
            assert_eq!(
                registration.transaction(&kind(name)).expect("read"),
                Some(source.to_owned()),
                "{name:?}"
            );
        }
        assert_eq!(registration.transaction(&kind("t2")).expect("read"), None);
    }
}

/// The README's name limit: the writer writes a type of 65,535 bytes, which reads back, and
/// refuses a type of 65,536.
#[test]
fn a_type_longer_than_a_name_holds_is_not_written() {
    let written = |name: &str| {
        let transactions =
            Keyed::new(vec![Entry::new(kind(name), SOURCE.to_owned())]).expect("a type");
        write(&honest_base(), &transactions)
    };
    let longest = "t".repeat(65_535);
    let blob = written(&longest).expect("written");
    let mut registration = Registration::open(Cursor::new(blob)).expect("opened");
    assert_eq!(
        registration.transaction(&kind(&longest)).expect("read"),
        Some(SOURCE.to_owned())
    );
    assert_eq!(
        written(&"t".repeat(65_536)),
        Err(RegisterError::Name { length: 65_536 })
    );
}

/// A reader whose blob holds `size` bytes it never reads.
struct Huge {
    size: u64,
    at: u64,
}

impl Read for Huge {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("a sized blob holds no bytes"))
    }
}

impl Seek for Huge {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.at = match to {
            SeekFrom::Start(at) => at,
            SeekFrom::End(delta) => self.size.checked_add_signed(delta).expect("a position"),
            SeekFrom::Current(delta) => self.at.checked_add_signed(delta).expect("a position"),
        };
        Ok(self.at)
    }
}

/// The rule a blob breaks: the error of opening it, else of reading `t1`'s source.
fn broken(blob: Vec<u8>) -> Malformed {
    let mut registration = match Registration::open(Cursor::new(blob)) {
        Ok(registration) => registration,
        Err(ReadError::Malformed(rule)) => return rule,
        Err(other) => panic!("no rule of the format: {other:?}"),
    };
    match registration.transaction(&kind("t1")) {
        Err(ReadError::Malformed(rule)) => rule,
        other => panic!("the registration reads: {other:?}"),
    }
}

/// One fixture per rule of the README's "Reading", each a change to the honest registration,
/// refused with the rule's error.
#[test]
fn a_registration_that_breaks_a_rule_is_refused_with_the_rule() {
    let honest_blob = laid_out(&honest(), &[]);
    let size = u32::try_from(honest_blob.len()).expect("a u32");
    assert!(
        Registration::open(Cursor::new(honest_blob.clone())).is_ok(),
        "the honest registration opens"
    );
    let changed = |position: usize, bytes: &[u8]| {
        let mut blob = honest_blob.clone();
        blob[position..position + bytes.len()].copy_from_slice(bytes);
        blob
    };
    let with = |change: &dyn Fn(&mut Vec<Record>)| {
        let mut records = honest();
        change(&mut records);
        laid_out(&records, &[])
    };
    let records = honest();
    let offset = |entry: usize| u32_at(&honest_blob, start_of(&records, entry) + 1);
    let length = |entry: usize| u32_at(&honest_blob, start_of(&records, entry) + 5);
    let span = {
        let mut blob = honest_blob.clone();
        let field = start_of(&records, 5) + 5;
        let grown = (length(5) + 1).to_le_bytes();
        blob[field..field + 4].copy_from_slice(&grown);
        blob
    };
    let tiling = {
        let mut blob = honest_blob.clone();
        let (bidi, on_error) = (start_of(&records, 2) + 1, start_of(&records, 3) + 1);
        blob[bidi..bidi + 4].copy_from_slice(&offset(3).to_le_bytes());
        blob[on_error..on_error + 4].copy_from_slice(&offset(2).to_le_bytes());
        blob
    };
    let mut trailing = honest_blob.clone();
    trailing.push(0);
    let fixtures: Vec<(&str, Vec<u8>, Malformed)> = vec![
        (
            "a truncated header",
            honest_blob[..15].to_vec(),
            Malformed::Header { size: 15 },
        ),
        ("another magic", changed(3, b"m"), Malformed::Magic),
        (
            "an unknown version",
            changed(8, &2_u32.to_le_bytes()),
            Malformed::Version { version: 2 },
        ),
        (
            "a directory past the blob's end",
            changed(12, &(size - 15).to_le_bytes()),
            Malformed::Directory {
                length: size - 15,
                size,
            },
        ),
        (
            "a directory that ends inside a record",
            laid_out(&honest(), &[6]),
            Malformed::Entry { entry: 6 },
        ),
        (
            "an unknown kind",
            with(&|records| records[5].code = 7),
            Malformed::Kind { entry: 5, code: 7 },
        ),
        (
            "a name that is no UTF-8",
            with(&|records| records[5].name = vec![0xFF]),
            Malformed::Name { entry: 5 },
        ),
        (
            "a named source",
            with(&|records| records[4].name = b"x".to_vec()),
            Malformed::Named {
                entry: 4,
                kind: Kind::Source,
            },
        ),
        (
            "a span past the blob's end",
            span,
            Malformed::Span {
                entry: 5,
                offset: offset(5),
                length: length(5) + 1,
                size,
            },
        ),
        (
            "entries out of their bytes' order",
            tiling,
            Malformed::Tiling {
                entry: 2,
                offset: offset(3),
                end: offset(2),
            },
        ),
        (
            "a byte after the last entry",
            trailing,
            Malformed::Trailing {
                end: size,
                size: size + 1,
            },
        ),
        (
            "a kind before the previous record's",
            with(&|records| records.swap(2, 3)),
            Malformed::Order { entry: 3 },
        ),
        (
            "a transaction type before the previous one",
            with(&|records| records.insert(5, named(6, b"t2", SOURCE.as_bytes()))),
            Malformed::Order { entry: 6 },
        ),
        (
            "a second locale",
            with(&|records| records.insert(1, record(1, b"de"))),
            Malformed::Repeated {
                entry: 1,
                kind: Kind::Locale,
            },
        ),
        (
            "a transaction type twice",
            with(&|records| records.push(named(6, b"t1", SOURCE.as_bytes()))),
            Malformed::Repeated {
                entry: 6,
                kind: Kind::Transaction,
            },
        ),
        (
            "no bidi entry",
            with(&|records| drop(records.remove(2))),
            Malformed::Missing { kind: Kind::Bidi },
        ),
        (
            "no source",
            with(&|records| drop(records.remove(4))),
            Malformed::Missing { kind: Kind::Source },
        ),
        (
            "a locale outside the canonical case",
            with(&|records| records[0].bytes = b"EN".to_vec()),
            Malformed::Locale { entry: 0 },
        ),
        (
            "an empty tag in the priority list",
            with(&|records| records[1].bytes = b"en,,de".to_vec()),
            Malformed::Priority { entry: 1 },
        ),
        (
            "a bidi byte of no choice",
            with(&|records| records[2].bytes = vec![2]),
            Malformed::Bidi { entry: 2 },
        ),
        (
            "an on-error entry of two bytes",
            with(&|records| records[3].bytes = vec![0, 1]),
            Malformed::OnError { entry: 3 },
        ),
        (
            "a source that is no UTF-8",
            with(&|records| records[4].bytes = vec![0xC3]),
            Malformed::Text { entry: 4 },
        ),
        (
            "a transaction source that is no UTF-8",
            with(&|records| records[5].bytes = vec![0xC3]),
            Malformed::Text { entry: 5 },
        ),
    ];
    for (case, blob, want) in fixtures {
        assert_eq!(broken(blob), want, "{case}");
    }
    let past = 1_u64 << 32;
    assert!(
        matches!(
            Registration::open(Huge { size: past, at: 0 }),
            Err(ReadError::Malformed(Malformed::Size { size })) if size == past
        ),
        "a blob past 4294967295 bytes"
    );
}

/// The context's rules over a registration that keeps the format's: a source that does not load,
/// sources of another locale than the locale entry's, and a transaction source of another
/// locale, each refused with its error.
#[test]
fn sources_that_do_not_build_the_context_are_refused() {
    let opened = |records: Vec<Record>| {
        Registration::open(Cursor::new(laid_out(&records, &[]))).expect("the format holds")
    };
    let mut records = honest();
    records[4].bytes = b"@locale en\n---\nbroken = {\n".to_vec();
    assert!(
        matches!(
            opened(records).base().context(),
            Err(ContextError::Source {
                at: 0,
                cause: LoadError::Syntax { .. }
            })
        ),
        "a source that does not load"
    );
    let mut records = honest();
    records[0].bytes = b"de".to_vec();
    assert_eq!(
        opened(records).base().context().map(|_| ()),
        Err(ContextError::Locale {
            locale: tag("de"),
            declared: Some(tag("en")),
        }),
        "sources of another locale"
    );
    let mut records = honest();
    records[5].bytes = b"@locale de\n---\n".to_vec();
    let text = request_naming(&["t1"]);
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    assert!(
        matches!(
            opened(records).context(&request),
            Err(ReadError::Context(ContextError::Transaction {
                ref kind,
                cause: LoadError::Locale { .. }
            })) if kind == "t1"
        ),
        "a transaction source of another locale"
    );
}

/// A reader over bytes that records each range of bytes it reads.
struct Counting {
    bytes: Vec<u8>,
    at: u64,
    reads: Vec<(u64, u64)>,
}

impl Read for Counting {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let start = usize::try_from(self.at).expect("a position");
        let rest = self.bytes.get(start..).unwrap_or_default();
        let count = rest.len().min(buf.len());
        buf[..count].copy_from_slice(&rest[..count]);
        let end = self.at + u64::try_from(count).expect("a count");
        if count > 0 {
            self.reads.push((self.at, end));
        }
        self.at = end;
        Ok(count)
    }
}

impl Seek for Counting {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let size = u64::try_from(self.bytes.len()).expect("a size");
        self.at = match to {
            SeekFrom::Start(at) => at,
            SeekFrom::End(delta) => size.checked_add_signed(delta).expect("a position"),
            SeekFrom::Current(delta) => self.at.checked_add_signed(delta).expect("a position"),
        };
        Ok(self.at)
    }
}

/// The ranges, adjacent ones joined.
fn joined(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (start, end) in ranges {
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

/// The bytes-read gate: over a registration of the test app's English sources and the types
/// `t0` and `t1`, a request that names `t1` reads the header, the directory, the base entries
/// and `t1`'s source, each once, and no byte of `t0`'s. The sizes come from the README's layout.
#[test]
fn a_request_reads_the_base_and_the_source_of_the_type_it_names() {
    let sources = Language::English.sources();
    let t0 = "@locale en\n---\n[gate]\nt0 = Type zero\n";
    let t1 = "@locale en\n---\n[gate]\nt1 = Type one\n";
    let base = Base {
        locale: tag("en"),
        priority: AllOf::new(vec![tag("en"), tag("de")]).expect("tags"),
        bidi: Bidi::None,
        on_error: OnRenderError::Rendered,
        sources: AllOf::new(sources.iter().map(|s| (*s).to_owned()).collect()).expect("sources"),
    };
    let transactions = Keyed::new(vec![
        Entry::new(kind("t1"), t1.to_owned()),
        Entry::new(kind("t0"), t0.to_owned()),
    ])
    .expect("types");
    let blob = write(&base, &transactions).expect("written");
    // The README's layout: 4 base records, a record per source, 2 named transaction records.
    let records = 4 + sources.len() + 2;
    let directory = 11 * records + 2 * "t0".len();
    let base_lengths: Vec<(String, usize)> = [
        ("locale".to_owned(), "en".len()),
        ("priority".to_owned(), "en,de".len()),
        ("bidi".to_owned(), 1),
        ("on_error".to_owned(), 1),
    ]
    .into_iter()
    .chain(
        sources
            .iter()
            .enumerate()
            .map(|(at, source)| (format!("source {at}"), source.len())),
    )
    .collect();
    let base_bytes: usize = base_lengths.iter().map(|(_, length)| length).sum();
    let base_end = 16 + directory + base_bytes;
    let t1_start = base_end + t0.len();
    assert_eq!(blob.len(), t1_start + t1.len(), "the README's layout");

    let text = request_naming(&["t1"]);
    let received = unsigned(&text).expect("received");
    let request: Request<'_> = request_of(&received).expect("request");
    let mut counting = Counting {
        bytes: blob,
        at: 0,
        reads: Vec::new(),
    };
    let context: Context = Registration::open(&mut counting)
        .expect("opened")
        .context(&request)
        .expect("the context");
    let as_u64 = |n: usize| u64::try_from(n).expect("a u64");
    let read: u64 = counting.reads.iter().map(|(start, end)| end - start).sum();
    assert_eq!(
        joined(counting.reads.clone()),
        [
            (0, as_u64(base_end)),
            (as_u64(t1_start), as_u64(t1_start + t1.len()))
        ],
        "the header, the directory, the base entries and t1's source"
    );
    assert_eq!(read, as_u64(base_end + t1.len()), "each byte read once");
    // The context words t1's source and the base sources, and nothing of t0's.
    let message = |id: &'static str| Bare(id);
    assert_eq!(
        context
            .resolve(&message("gate.t1"))
            .map(|text| text.to_string()),
        Ok("Type one".to_owned())
    );
    assert!(matches!(
        context.resolve(&message("gate.t0")),
        Err(ResolveError::Unknown { .. })
    ));
    assert_eq!(
        context
            .resolve(&siros_openid4vp::rows::WalletText::None)
            .map(|text| text.to_string()),
        Ok("None".to_owned())
    );
    let sizes: Vec<String> = base_lengths
        .iter()
        .map(|(entry, length)| format!("{entry} {length}"))
        .collect();
    println!(
        "read {read} of {} bytes: header 16, directory {directory}, {}, t1 {}; t0's {} unread",
        t1_start + t1.len(),
        sizes.join(", "),
        t1.len(),
        t0.len()
    );
}

/// A message with an id and no arguments.
struct Bare(&'static str);

impl siros_i18n::Message for Bare {
    fn id(&self) -> &str {
        self.0
    }

    fn args(&self, _: &mut dyn FnMut(&str, &dyn std::fmt::Display)) {}
}
