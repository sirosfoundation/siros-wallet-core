//! What a registration holds, and the constants of its format (the crate README's "Format").

use std::fmt;

use siros_explain::Explain;
use siros_i18n::{Bidi, Context, LoadError, LocaleTag};
use siros_syntax::AllOf;

/// The bytes a registration starts with.
pub(crate) const MAGIC: [u8; 8] = [0x89, b'S', b'C', b'M', b'\r', b'\n', 0x1a, b'\n'];

/// The version this crate writes and reads.
pub(crate) const VERSION: u32 = 1;

/// The header's bytes: the magic, the version and the directory's length.
pub(crate) const HEADER: u32 = 16;

/// The separator between two tags of the priority list.
pub(crate) const COMMA: char = ',';

/// A kind of entry, which the directory writes as its code. Kinds order as their codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// The locale the wallet wrote the registration in. Code 1, one entry.
    Locale,
    /// The End-User's ranked language tags. Code 2, one entry.
    Priority,
    /// The wallet's bidi choice. Code 3, one entry.
    Bidi,
    /// The app's on-error choice. Code 4, one entry.
    OnError,
    /// One of the wallet's MF2 sources for the matcher. Code 5, one entry or more.
    Source,
    /// A registered transaction type's converted View source. Code 6, any number of entries.
    Transaction,
}

impl Kind {
    /// Every kind, in the directory's order.
    const ALL: [Self; 6] = [
        Self::Locale,
        Self::Priority,
        Self::Bidi,
        Self::OnError,
        Self::Source,
        Self::Transaction,
    ];

    /// The code the directory writes.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Locale => 1,
            Self::Priority => 2,
            Self::Bidi => 3,
            Self::OnError => 4,
            Self::Source => 5,
            Self::Transaction => 6,
        }
    }

    /// The kind of a code; `None` for a code version 1 does not define.
    pub(crate) fn of(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.code() == code)
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Locale => "locale",
            Self::Priority => "priority",
            Self::Bidi => "bidi",
            Self::OnError => "on_error",
            Self::Source => "source",
            Self::Transaction => "transaction",
        })
    }
}

/// What the matcher emits when a text of its entries does not resolve or a row has no name: the
/// app's choice, which the registration carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OnRenderError {
    /// No entry.
    NoEntry,
    /// The entries whose texts resolved.
    Rendered,
}

impl OnRenderError {
    /// The byte its entry holds.
    #[cfg(feature = "register")]
    pub(crate) const fn byte(self) -> u8 {
        match self {
            Self::NoEntry => 0,
            Self::Rendered => 1,
        }
    }

    /// The choice its entry's byte writes; `None` for a byte no choice writes.
    pub(crate) const fn of(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::NoEntry),
            1 => Some(Self::Rendered),
            _ => None,
        }
    }
}

/// The byte a bidi entry holds.
#[cfg(feature = "register")]
pub(crate) const fn bidi_byte(bidi: Bidi) -> u8 {
    match bidi {
        Bidi::Default => 0,
        Bidi::None => 1,
    }
}

/// The bidi choice a bidi entry's byte writes; `None` for a byte no choice writes.
pub(crate) const fn bidi_of(byte: u8) -> Option<Bidi> {
    match byte {
        0 => Some(Bidi::Default),
        1 => Some(Bidi::None),
        _ => None,
    }
}

/// The tag `text` writes; `None` for a text that is no tag, or that writes one outside its
/// canonical case.
pub(crate) fn canonical_tag(text: &str) -> Option<LocaleTag> {
    LocaleTag::parse(text)
        .ok()
        .filter(|tag| tag.as_str() == text)
}

/// The entries every request reads: the matcher's context and `Env` come from them, and its
/// emission's on-error choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base {
    /// The locale the wallet wrote the registration in: every source's `@locale`. The wallet
    /// registers anew when its language changes.
    pub locale: LocaleTag,
    /// The End-User's ranked language tags: the matcher's `Env::priority`, over which the claims
    /// kit picks a display entry (`format_entry`) and siros-paso runs PaSO View §4's Lookup.
    pub priority: AllOf<LocaleTag>,
    /// The wallet's bidi choice, which the matcher's context applies.
    pub bidi: Bidi,
    /// The app's choice for an entry that does not show.
    pub on_error: OnRenderError,
    /// The wallet's MF2 resources for the matcher, in load order, its formats first.
    pub sources: AllOf<String>,
}

impl Base {
    /// The matcher's context before a request: the sources loaded in their order under `bidi`.
    /// The wallet builds it to check a registration before writing it.
    ///
    /// # Errors
    ///
    /// [`ContextError::Source`] for the first source the context refuses, and
    /// [`ContextError::Locale`] when the sources declare another locale than `locale`.
    pub fn context(&self) -> Result<Context, ContextError> {
        let mut context = Context::new().bidi(self.bidi);
        for (at, source) in self.sources.items().iter().enumerate() {
            context = context
                .module(source)
                .map_err(|cause| ContextError::Source { at, cause })?;
        }
        match context.locale() {
            Some(locale) if *locale == self.locale => Ok(context),
            declared => Err(ContextError::Locale {
                locale: self.locale.clone(),
                declared: declared.cloned(),
            }),
        }
    }
}

/// Why the matcher's context does not build from a registration's sources.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum ContextError {
    /// A base source the context refuses.
    #[error("source {at} of the registration does not load")]
    #[explain(id = "context.source")]
    Source {
        /// Its position in load order, from 0.
        at: usize,
        /// The refusal.
        #[source]
        cause: LoadError,
    },
    /// A transaction type's source the context refuses.
    #[error("the source of the transaction type {kind:?} does not load")]
    #[explain(id = "context.transaction")]
    Transaction {
        /// The type.
        kind: String,
        /// The refusal.
        #[source]
        cause: LoadError,
    },
    /// The sources declare another locale than the one the registration records.
    #[error("the sources declare another locale than the registration's {locale}")]
    #[explain(id = "context.locale")]
    Locale {
        /// The locale the registration records.
        locale: LocaleTag,
        /// The sources' `@locale`; `None` when no source sets one.
        declared: Option<LocaleTag>,
    },
}
