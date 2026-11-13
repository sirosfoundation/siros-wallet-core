//! Writes the default text of a language's format options for siros-i18n modules from CLDR's
//! JSON release 49.0.0 (github.com/unicode-org/cldr-json, tag `49.0.0`), the release ICU4X 2.4's
//! compiled data was generated from. A wallet's author copies the output's head and its
//! `[formats.<format>]` sections into a module of the language, keeps or edits them, and a
//! context checks them as it loads the module.
//!
//! Usage: `siros-cldr <cldr-json directory> <language>`, the directory holding `cldr-core`,
//! `cldr-numbers-full`, `cldr-dates-full` and `cldr-misc-full`. The resource is written to
//! standard output. siros-i18n's test fixtures `crates/siros-i18n/tests/cldr/<language>.mf2` are
//! its output for en, de, es, fr and he, and siros-testkit's `crates/siros-testkit/locales/cldr/`
//! for en and de.

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

mod cldr;
mod write;

use std::io::Write as _;
use std::path::PathBuf;

use cldr::{Cldr, CldrError};

siros_explain::scope!("cldr");

/// The CLDR release the tool reads.
const RELEASE: &str = "49.0.0";

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [root, language] = args.as_slice() else {
        eprintln!("usage: siros-cldr <cldr-json directory> <language>");
        return std::process::ExitCode::from(2);
    };
    match run(PathBuf::from(root), language) {
        Ok(text) => match std::io::stdout().write_all(text.as_bytes()) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("siros-cldr: {error}");
                std::process::ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("siros-cldr: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(root: PathBuf, language: &str) -> Result<String, CldrError> {
    let cldr = Cldr::open(root, language, RELEASE)?;
    write::resource(&cldr, RELEASE)
}
