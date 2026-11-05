//! Reading CLDR's JSON files for one language.

use std::path::PathBuf;

use serde_json::Value;

/// Why the tool writes nothing.
#[derive(Debug, thiserror::Error, siros_explain::Explain)]
#[explain(domain = "cldr")]
pub(crate) enum CldrError {
    /// A file does not read.
    #[error("{path} does not read: {cause}")]
    Read {
        /// The file.
        path: String,
        /// The I/O error, as written.
        cause: String,
    },
    /// A file is no JSON.
    #[error("{path} is no JSON: {cause}")]
    Json {
        /// The file.
        path: String,
        /// The parser's error, as written.
        cause: String,
    },
    /// A package of the directory is of another CLDR release.
    #[error("{package} is of CLDR {found}, and the tool reads {wanted}")]
    Release {
        /// The package.
        package: &'static str,
        /// The release found.
        found: String,
        /// The release read.
        wanted: &'static str,
    },
    /// A value the tool reads is absent or no text.
    #[error("{path} lacks the text at {at}")]
    Missing {
        /// The file.
        path: String,
        /// The value's path.
        at: String,
    },
    /// A text holds a character the resource format cannot carry.
    #[error("the text {text} holds a backslash or a line break")]
    Unwritable {
        /// The text.
        text: String,
    },
}

/// One file, read.
pub(crate) struct File {
    path: String,
    json: Value,
}

impl File {
    /// The value at `at`, a path of object keys.
    pub(crate) fn value(&self, at: &[&str]) -> Result<&Value, CldrError> {
        at.iter()
            .try_fold(&self.json, |value, key| value.get(key))
            .ok_or_else(|| self.missing(at))
    }

    /// The text at `at`.
    pub(crate) fn text(&self, at: &[&str]) -> Result<&str, CldrError> {
        self.value(at)?.as_str().ok_or_else(|| self.missing(at))
    }

    /// The object at `at`, its members in key order.
    pub(crate) fn object(&self, at: &[&str]) -> Result<&serde_json::Map<String, Value>, CldrError> {
        self.value(at)?.as_object().ok_or_else(|| self.missing(at))
    }

    pub(crate) fn missing(&self, at: &[&str]) -> CldrError {
        CldrError::Missing {
            path: self.path.clone(),
            at: at.join("/"),
        }
    }
}

/// The packages the tool reads.
const PACKAGES: [&str; 4] = [
    "cldr-core",
    "cldr-numbers-full",
    "cldr-dates-full",
    "cldr-misc-full",
];

/// A CLDR JSON directory and the language read from it.
pub(crate) struct Cldr {
    root: PathBuf,
    pub(crate) language: String,
}

impl Cldr {
    /// The directory, each package it reads checked to be of `release`.
    pub(crate) fn open(
        root: PathBuf,
        language: &str,
        release: &'static str,
    ) -> Result<Self, CldrError> {
        let cldr = Self {
            root,
            language: language.to_owned(),
        };
        for package in PACKAGES {
            let file = cldr.file(&format!("{package}/package.json"))?;
            let found = file.text(&["version"])?;
            if found != release {
                return Err(CldrError::Release {
                    package,
                    found: found.to_owned(),
                    wanted: release,
                });
            }
        }
        Ok(cldr)
    }

    /// The file at `relative`.
    pub(crate) fn file(&self, relative: &str) -> Result<File, CldrError> {
        let path = self.root.join(relative);
        let shown = path.display().to_string();
        let text = std::fs::read_to_string(&path).map_err(|error| CldrError::Read {
            path: shown.clone(),
            cause: error.to_string(),
        })?;
        let json = serde_json::from_str(&text).map_err(|error| CldrError::Json {
            path: shown.clone(),
            cause: error.to_string(),
        })?;
        Ok(File { path: shown, json })
    }

    /// The language's file `name` of the package `package`, under `main/<language>`.
    pub(crate) fn main(&self, package: &str, name: &str) -> Result<File, CldrError> {
        self.file(&format!("{package}/main/{}/{name}", self.language))
    }
}
