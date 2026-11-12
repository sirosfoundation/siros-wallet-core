//! The registration's format, as the crate README's "Format" lays it out: the writer writes that
//! layout and the reader gives back what was written; a registration that breaks a rule is
//! refused with that rule's error; sources that do not load are refused by the base, the writer
//! and the reader; one source under two types is written and loads; a request reads the header,
//! the directory, the base entries and the source of the transaction type it names, and no other
//! byte.

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use siros_credman::register::{RegisterError, write};
use siros_credman::{Base, ContextError, Kind, Malformed, ReadError, Registration};
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
/// Default Bidi Strategy, one source and the type `t1`.
fn honest() -> Vec<Record> {
    vec![
        record(1, b"en"),
        record(2, b"en,de-CH"),
        record(3, &[0]),
        record(4, SOURCE.as_bytes()),
        named(5, b"t1", SOURCE.as_bytes()),
    ]
}

/// What the honest records hold.
fn honest_base() -> Base {
    Base::load(
        tag("en"),
        AllOf::new(vec![tag("en"), tag("de-CH")]).expect("tags"),
        Bidi::Default,
        AllOf::one(SOURCE.to_owned()),
    )
    .expect("the honest base loads")
}

fn types(given: &[(&str, &str)]) -> Keyed<TransactionType<'static>, String> {
    Keyed::new(
        given
            .iter()
            .map(|(name, source)| Entry::new(kind(name), (*source).to_owned()))
            .collect(),
    )
    .expect("distinct types")
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
/// base, and every transaction type's source, the types listed ascending; a request naming every
/// type loads its context.
#[test]
fn the_reader_gives_back_what_the_writer_writes() {
    assert_eq!(
        write(&honest_base(), &types(&[("t1", SOURCE)])).expect("written"),
        laid_out(&honest(), &[]),
        "the writer writes the README's layout"
    );
    let bases = [
        honest_base(),
        Base::load(
            tag("zh-Hant-TW"),
            AllOf::new(vec![tag("zh-Hant-TW"), tag("en"), tag("de-CH-x-phonebk")]).expect("tags"),
            Bidi::None,
            AllOf::new(vec![
                "@locale zh-Hant-TW\n---\n".to_owned(),
                "@locale zh-Hant-TW\n---\n[first]\nlabel = first\n".to_owned(),
                "@locale zh-Hant-TW\n---\n[third]\nlabel = third, بالعربية\n".to_owned(),
            ])
            .expect("sources"),
        )
        .expect("the base loads"),
    ];
    // Given out of order: the directory lists them ascending by their UTF-8 bytes.
    let given = [
        ("urn:example:payment", "a payment"),
        ("", "the empty type"),
        ("Ünicode", "a type past ASCII"),
        ("t1", "t1's source"),
    ];
    let mut ascending: Vec<&str> = given.iter().map(|(name, _)| *name).collect();
    ascending.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let text = request_naming(&ascending);
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    for base in bases {
        let source = |at: usize, label: &str| {
            format!(
                "@locale {}\n---\n[type{at}]\nlabel = {label}\n",
                base.locale()
            )
        };
        let sources: Vec<(&str, String)> = given
            .iter()
            .enumerate()
            .map(|(at, (name, label))| (*name, source(at, label)))
            .collect();
        let keyed: Vec<(&str, &str)> = sources
            .iter()
            .map(|(name, source)| (*name, source.as_str()))
            .collect();
        let blob = write(&base, &types(&keyed)).expect("written");
        let mut registration = Registration::open(Cursor::new(blob)).expect("opened");
        assert_eq!(registration.base(), &base);
        let listed: Vec<&str> = registration
            .transactions()
            .map(TransactionType::as_str)
            .collect();
        assert_eq!(listed, ascending);
        for (name, source) in &sources {
            assert_eq!(
                registration.transaction(&kind(name)).expect("read"),
                Some(source.clone()),
                "{name:?}"
            );
        }
        assert_eq!(registration.transaction(&kind("t2")).expect("read"), None);
        let context = registration
            .context(&request)
            .expect("a written registration loads");
        assert_eq!(
            context
                .resolve(&Bare("type3.label"))
                .map(|text| text.to_string()),
            Ok("t1's source".to_owned())
        );
    }
}

/// The README's name limit: the writer writes a type of 65,535 bytes, which reads back, and
/// refuses a type of 65,536.
#[test]
fn a_type_longer_than_a_name_holds_is_not_written() {
    let written = |name: &str| write(&honest_base(), &types(&[(name, SOURCE)]));
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
        let field = start_of(&records, 4) + 5;
        let grown = (length(4) + 1).to_le_bytes();
        blob[field..field + 4].copy_from_slice(&grown);
        blob
    };
    let tiling = {
        let mut blob = honest_blob.clone();
        let (priority, bidi) = (start_of(&records, 1) + 1, start_of(&records, 2) + 1);
        blob[priority..priority + 4].copy_from_slice(&offset(2).to_le_bytes());
        blob[bidi..bidi + 4].copy_from_slice(&offset(1).to_le_bytes());
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
            laid_out(&honest(), &[5]),
            Malformed::Entry { entry: 5 },
        ),
        (
            "an unknown kind",
            with(&|records| records[4].code = 6),
            Malformed::Kind { entry: 4, code: 6 },
        ),
        (
            "a name that is no UTF-8",
            with(&|records| records[4].name = vec![0xFF]),
            Malformed::Name { entry: 4 },
        ),
        (
            "a named source",
            with(&|records| records[3].name = b"x".to_vec()),
            Malformed::Named {
                entry: 3,
                kind: Kind::Source,
            },
        ),
        (
            "a span past the blob's end",
            span,
            Malformed::Span {
                entry: 4,
                offset: offset(4),
                length: length(4) + 1,
                size,
            },
        ),
        (
            "entries out of their bytes' order",
            tiling,
            Malformed::Tiling {
                entry: 1,
                offset: offset(2),
                end: offset(1),
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
            with(&|records| records.insert(4, named(5, b"t2", SOURCE.as_bytes()))),
            Malformed::Order { entry: 5 },
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
            with(&|records| records.push(named(5, b"t1", SOURCE.as_bytes()))),
            Malformed::Repeated {
                entry: 5,
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
            with(&|records| drop(records.remove(3))),
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
            "a bidi entry of two bytes",
            with(&|records| records[2].bytes = vec![0, 0]),
            Malformed::Bidi { entry: 2 },
        ),
        (
            "a source that is no UTF-8",
            with(&|records| records[3].bytes = vec![0xC3]),
            Malformed::Text { entry: 3 },
        ),
        (
            "a transaction source that is no UTF-8",
            with(&|records| records[4].bytes = vec![0xC3]),
            Malformed::Text { entry: 4 },
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

/// Sources that do not load: [`Base::load`] refuses a base source that does not load and
/// sources of another locale; the writer refuses a type's source that loads only after another
/// type's, and two types' sources that word one id; the reader refuses a blob whose base source,
/// or whose named type's source, does not load.
#[test]
fn sources_that_do_not_load_are_refused() {
    let base = |locale: &str, sources: &[&str]| {
        Base::load(
            tag(locale),
            AllOf::one(tag("en")),
            Bidi::Default,
            AllOf::new(sources.iter().map(|source| (*source).to_owned()).collect())
                .expect("sources"),
        )
    };
    let broken = "@locale en\n---\nbroken = {\n";
    assert!(
        matches!(
            base("en", &[SOURCE, broken]),
            Err(ContextError::Source {
                at: 1,
                cause: LoadError::Syntax { .. }
            })
        ),
        "a base source that does not load"
    );
    assert_eq!(
        base("de", &[SOURCE]).map(|_| ()),
        Err(ContextError::Locale {
            locale: tag("de"),
            declared: Some(tag("en")),
        }),
        "sources of another locale"
    );

    // t1 calls :number, whose options t0's source defines: t1 loads after t0, and alone it does
    // not.
    let [cldr, ..] = Language::English.sources();
    let counting = "@locale en\n---\n[t1]\ncount = {$value :number}\n";
    assert_eq!(
        write(&honest_base(), &types(&[("t0", cldr), ("t1", counting)])),
        Err(RegisterError::Transaction {
            kind: kind("t1"),
            cause: LoadError::Option {
                id: "t1.count".to_owned(),
                function: "number".to_owned(),
            },
        }),
        "a source that loads only after another type's"
    );
    let zero = "@locale en\n---\n[gate]\nlabel = Zero\n";
    let one = "@locale en\n---\n[gate]\nlabel = One\n";
    assert_eq!(
        write(&honest_base(), &types(&[("t0", zero), ("t1", one)])),
        Err(RegisterError::Transaction {
            kind: kind("t1"),
            cause: LoadError::Repeated {
                id: "gate.label".to_owned(),
            },
        }),
        "two sources that word one id"
    );

    let mut records = honest();
    records[3].bytes = broken.as_bytes().to_vec();
    assert!(
        matches!(
            Registration::open(Cursor::new(laid_out(&records, &[]))),
            Err(ReadError::Context(ContextError::Source {
                at: 0,
                cause: LoadError::Syntax { .. }
            }))
        ),
        "a blob whose base source does not load"
    );
    let mut records = honest();
    records[4].bytes = b"@locale de\n---\n".to_vec();
    let text = request_naming(&["t1"]);
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let mut registration =
        Registration::open(Cursor::new(laid_out(&records, &[]))).expect("the base loads");
    assert!(
        matches!(
            registration.context(&request),
            Err(ReadError::Context(ContextError::Transaction {
                ref kind,
                cause: LoadError::Locale { .. }
            })) if kind.as_str() == "t1"
        ),
        "a blob whose named type's source does not load"
    );
}

/// Two types whose metadata is one object convert to one source: the writer writes it under each
/// type, and a request naming both types loads it.
#[test]
fn one_source_under_two_types_is_written_and_loads() {
    let one = "@locale en\n---\n[gate]\nlabel = One\n";
    let blob = write(&honest_base(), &types(&[("t0", one), ("t1", one)])).expect("written");
    let mut registration = Registration::open(Cursor::new(blob)).expect("opened");
    for name in ["t0", "t1"] {
        assert_eq!(
            registration.transaction(&kind(name)).expect("read"),
            Some(one.to_owned()),
            "{name}"
        );
    }
    let text = request_naming(&["t0", "t1"]);
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let context = registration
        .context(&request)
        .expect("a request naming both types loads");
    assert_eq!(
        context
            .resolve(&Bare("gate.label"))
            .map(|text| text.to_string()),
        Ok("One".to_owned())
    );
}

/// The writer refuses a base source and a type's source holding a variant key that Unicode
/// Normalization Form C changes, which [`Base::load`] takes, and writes them with the key in NFC.
/// U+1E0A U+0323 is outside NFC, which writes it U+1E0C U+0307 (UAX #15).
#[test]
fn a_key_outside_nfc_is_not_written() {
    const WRITTEN: &str = "\u{1E0A}\u{323}";
    const NORMAL: &str = "\u{1E0C}\u{307}";
    let source = |section: &str, key: &str| {
        format!(
            "@locale en\n---\n[{section}]\nlabel = .input {{$x :string}} .match $x {key} {{{{a}}}} * {{{{b}}}}\n"
        )
    };
    let base = |second: String| {
        Base::load(
            tag("en"),
            AllOf::one(tag("en")),
            Bidi::Default,
            AllOf::new(vec![SOURCE.to_owned(), second]).expect("sources"),
        )
        .expect("the reader's load takes it")
    };
    let unnormalized = LoadError::Unnormalized {
        id: "gate.label".to_owned(),
        text: WRITTEN.to_owned(),
    };
    assert_eq!(
        write(&base(source("gate", WRITTEN)), &Keyed::empty()),
        Err(RegisterError::Source {
            at: 1,
            cause: unnormalized.clone(),
        }),
        "a base source"
    );
    assert_eq!(
        write(&honest_base(), &types(&[("t1", &source("gate", WRITTEN))])),
        Err(RegisterError::Transaction {
            kind: kind("t1"),
            cause: unnormalized,
        }),
        "a type's source"
    );
    assert_eq!(
        write(
            &base(source("gate", NORMAL)),
            &types(&[("t1", &source("t1", NORMAL))])
        )
        .map(|_| ()),
        Ok(()),
        "the sources with the key in NFC"
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
    let base = Base::load(
        tag("en"),
        AllOf::new(vec![tag("en"), tag("de")]).expect("tags"),
        Bidi::None,
        AllOf::new(sources.iter().map(|s| (*s).to_owned()).collect()).expect("sources"),
    )
    .expect("the base loads");
    let blob = write(&base, &types(&[("t1", t1), ("t0", t0)])).expect("written");
    // The README's layout: 3 base records, a record per source, 2 named transaction records.
    let records = 3 + sources.len() + 2;
    let directory = 11 * records + 2 * "t0".len();
    let base_lengths: Vec<(String, usize)> = [
        ("locale".to_owned(), "en".len()),
        ("priority".to_owned(), "en,de".len()),
        ("bidi".to_owned(), 1),
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

    fn arg(&self, _: &str) -> Option<&dyn siros_i18n::Arg> {
        None
    }
}
