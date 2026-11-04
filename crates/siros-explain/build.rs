//! Remaps iso_currency's ISO 4217 table into what the matcher reads: each alphabetic code packed
//! in 15 bits (5 per letter), ascending, and its minor units (255: none listed).

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

use iso_currency::{Currency, IntoEnumIterator};

/// One currency of the table: its packed code, then its minor units, so rows sort by code.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Row {
    packed: u16,
    minor: u8,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rerun-if-changed=build.rs");
    let mut rows = Vec::new();
    for currency in Currency::iter() {
        let packed = currency.code().bytes().try_fold(0u16, |v, b| {
            b.is_ascii_uppercase().then(|| v * 32 + u16::from(b - b'A'))
        });
        let minor = match currency.exponent() {
            None => 255,
            Some(e) => u8::try_from(e)?,
        };
        rows.push(Row {
            packed: packed.ok_or("a code outside A-Z")?,
            minor,
        });
    }
    rows.sort_unstable();
    let codes: Vec<u16> = rows.iter().map(|row| row.packed).collect();
    let minor: Vec<u8> = rows.iter().map(|row| row.minor).collect();
    let mut out = String::new();
    writeln!(
        out,
        "pub(crate) const CODES: [u16; {}] = {codes:?};",
        codes.len()
    )?;
    writeln!(
        out,
        "pub(crate) const MINOR: [u8; {}] = {minor:?};",
        minor.len()
    )?;
    let path = std::path::Path::new(&std::env::var("OUT_DIR")?).join("iso4217.rs");
    std::fs::write(path, out)?;
    Ok(())
}
