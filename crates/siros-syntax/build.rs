//! Reads SIX's ISO 4217 List One, `list-one.xml`, into the rows `Currency` reads: one row per
//! alphabetic code, the code packed in 15 bits (5 per letter) as two big-endian bytes, then its
//! minor units (255 for `N.A.`), the rows ascending by code. An entry is a country without a
//! universal currency, or a currency with its alphabetic code, numeric code and minor units. Any
//! other text fails the build, as does a code listed with two minor units.

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

use std::fmt::Write as _;

/// One currency: its packed code, then its minor units, so rows sort by code.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Row {
    packed: u16,
    minor: u8,
}

/// The file's text from byte `at` on.
struct Cursor<'a> {
    rest: &'a str,
    at: usize,
}

/// The refusal at byte `at`, which names what List One's form holds there.
fn refusal(at: usize, expected: &str) -> String {
    format!("list-one.xml, byte {at}: {expected} expected")
}

impl<'a> Cursor<'a> {
    /// The refusal at the cursor.
    fn refuse(&self, expected: &str) -> String {
        refusal(self.at, expected)
    }

    /// The next `length` bytes, taken.
    fn take(&mut self, length: usize) -> Option<&'a str> {
        let (taken, rest) = self.rest.split_at_checked(length)?;
        self.rest = rest;
        self.at += length;
        Some(taken)
    }

    /// Whether the text starts with `literal`, taken.
    fn eat(&mut self, literal: &str) -> bool {
        self.rest.starts_with(literal) && self.take(literal.len()).is_some()
    }

    /// Takes `literal`.
    fn expect(&mut self, literal: &str) -> Result<(), String> {
        if self.eat(literal) {
            Ok(())
        } else {
            Err(self.refuse(&format!("`{literal}`")))
        }
    }

    /// Takes XML's white space.
    fn space(&mut self) {
        let kept = self.rest.trim_start_matches([' ', '\t', '\r', '\n']);
        self.at += self.rest.len() - kept.len();
        self.rest = kept;
    }

    /// Takes white space and the start tag `<name>`.
    fn open(&mut self, name: &str) -> Result<(), String> {
        self.space();
        self.expect(&format!("<{name}>"))
    }

    /// The text before `</name>`, which `read` takes, and the end tag. The text holds neither
    /// markup nor a reference.
    fn text<T>(&mut self, name: &str, read: fn(&str) -> Option<T>) -> Result<T, String> {
        let at = self.at;
        let length = self
            .rest
            .find(['<', '&'])
            .ok_or_else(|| refusal(self.at + self.rest.len(), &format!("`</{name}>`")))?;
        let value = self
            .take(length)
            .and_then(read)
            .ok_or_else(|| refusal(at, &format!("the text of a `<{name}>`")))?;
        self.expect(&format!("</{name}>"))?;
        Ok(value)
    }

    /// The element `<name>`, after white space, its text taken by `read`.
    fn element<T>(&mut self, name: &str, read: fn(&str) -> Option<T>) -> Result<T, String> {
        self.open(name)?;
        self.text(name, read)
    }
}

/// A name: some text.
fn named(text: &str) -> Option<()> {
    (!text.is_empty()).then_some(())
}

/// An alphabetic code, packed: three uppercase letters.
fn packed(code: &str) -> Option<u16> {
    if code.len() != 3 {
        return None;
    }
    code.bytes().try_fold(0u16, |packed, letter| {
        letter
            .is_ascii_uppercase()
            .then(|| packed * 32 + u16::from(letter - b'A'))
    })
}

/// A numeric code: three digits.
fn numeric(code: &str) -> Option<()> {
    (code.len() == 3 && code.bytes().all(|digit| digit.is_ascii_digit())).then_some(())
}

/// Minor units: one digit, or `N.A.` as 255.
fn minor(units: &str) -> Option<u8> {
    match units.as_bytes() {
        b"N.A." => Some(255),
        &[digit] if digit.is_ascii_digit() => Some(digit - b'0'),
        _ => None,
    }
}

/// A date: `YYYY-MM-DD`.
fn date(text: &str) -> Option<()> {
    let digits = |part: &str| part.bytes().all(|digit| digit.is_ascii_digit());
    match text.split('-').collect::<Vec<_>>().as_slice() {
        [year, month, day] if year.len() == 4 && month.len() == 2 && day.len() == 2 => {
            (digits(year) && digits(month) && digits(day)).then_some(())
        }
        _ => None,
    }
}

/// The row of the entry after `<CcyNtry>`, `None` for a country without a universal currency.
fn entry(cursor: &mut Cursor<'_>) -> Result<Option<Row>, String> {
    cursor.element("CtryNm", named)?;
    cursor.space();
    if !cursor.eat("<CcyNm>") {
        cursor.expect("<CcyNm IsFund=\"true\">")?;
    }
    cursor.text("CcyNm", named)?;
    cursor.space();
    if cursor.eat("</CcyNtry>") {
        return Ok(None);
    }
    let packed = cursor.element("Ccy", packed)?;
    cursor.element("CcyNbr", numeric)?;
    let minor = cursor.element("CcyMnrUnts", minor)?;
    cursor.space();
    cursor.expect("</CcyNtry>")?;
    Ok(Some(Row { packed, minor }))
}

/// The rows of `file`, one per entry with a currency.
fn rows(file: &str) -> Result<Vec<Row>, String> {
    let mut cursor = Cursor { rest: file, at: 0 };
    cursor.expect(r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#)?;
    cursor.space();
    cursor.expect(r#"<ISO_4217 Pblshd=""#)?;
    let at = cursor.at;
    cursor
        .take(10)
        .and_then(date)
        .ok_or_else(|| refusal(at, "the publication date"))?;
    cursor.expect(r#"">"#)?;
    cursor.open("CcyTbl")?;
    let mut rows = Vec::new();
    loop {
        cursor.space();
        if cursor.eat("</CcyTbl>") {
            break;
        }
        cursor.expect("<CcyNtry>")?;
        rows.extend(entry(&mut cursor)?);
    }
    cursor.space();
    cursor.expect("</ISO_4217>")?;
    cursor.space();
    if cursor.rest.is_empty() {
        Ok(rows)
    } else {
        Err(cursor.refuse("the end of the file"))
    }
}

/// The code's letters.
fn letters(packed: u16) -> String {
    [10, 5, 0]
        .into_iter()
        .map(|shift| char::from(b'A' + ((packed >> shift) & 31) as u8))
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=list-one.xml");
    let path = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR")?).join("list-one.xml");
    let mut rows = rows(&std::fs::read_to_string(path)?)?;
    rows.sort_unstable();
    rows.dedup();
    if let Some([row, _]) = rows
        .windows(2)
        .find(|pair| matches!(pair, [a, b] if a.packed == b.packed))
    {
        return Err(format!(
            "list-one.xml lists {} with two minor units",
            letters(row.packed)
        )
        .into());
    }
    let rows: Vec<[u8; 3]> = rows
        .iter()
        .map(|row| {
            let [high, low] = row.packed.to_be_bytes();
            [high, low, row.minor]
        })
        .collect();
    let mut out = String::new();
    writeln!(
        out,
        "pub(crate) const CURRENCIES: [[u8; 3]; {}] = {rows:?};",
        rows.len()
    )?;
    let path = std::path::Path::new(&std::env::var("OUT_DIR")?).join("iso4217.rs");
    std::fs::write(path, out)?;
    Ok(())
}
