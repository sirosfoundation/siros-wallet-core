//! What a registration holds, and the constants of its format (the crate README's "Format").

use std::fmt;

use siros_explain::Explain;
use siros_i18n::{Bidi, Context, LoadError, LocaleTag};
use siros_openid4vp::ids::TransactionType;
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
    /// One of the wallet's MF2 sources for the matcher. Code 4, one entry or more.
    Source,
    /// A registered transaction type's converted View source. Code 5, any number of entries.
    Transaction,
}

impl Kind {
    /// Every kind, in the directory's order.
    const ALL: [Self; 5] = [
        Self::Locale,
        Self::Priority,
        Self::Bidi,
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
            Self::Source => 4,
            Self::Transaction => 5,
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
            Self::Source => "source",
            Self::Transaction => "transaction",
        })
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

/// The entries every request reads, and the matcher's context before a request, which they load.
/// Only [`Base::load`] makes one, so a base's sources load.
#[derive(Debug, Clone)]
pub struct Base {
    locale: LocaleTag,
    priority: AllOf<LocaleTag>,
    bidi: Bidi,
    sources: AllOf<String>,
    context: Context,
}

impl Base {
    /// The base whose context loads `sources` in their order under `bidi`, in the locale
    /// `locale`. The wallet registers anew when its language changes.
    ///
    /// # Errors
    ///
    /// [`ContextError::Source`] for the first source the context refuses, and
    /// [`ContextError::Locale`] when the sources declare another locale than `locale`.
    pub fn load(
        locale: LocaleTag,
        priority: AllOf<LocaleTag>,
        bidi: Bidi,
        sources: AllOf<String>,
    ) -> Result<Self, ContextError> {
        let context = sources.items().iter().enumerate().try_fold(
            Context::new().bidi(bidi),
            |context, (at, source)| {
                context
                    .module(source)
                    .map_err(|cause| ContextError::Source { at, cause })
            },
        )?;
        if context.locale() != Some(&locale) {
            return Err(ContextError::Locale {
                declared: context.locale().cloned(),
                locale,
            });
        }
        Ok(Self {
            locale,
            priority,
            bidi,
            sources,
            context,
        })
    }

    /// The locale the wallet wrote the registration in: every source's `@locale`.
    #[must_use]
    pub const fn locale(&self) -> &LocaleTag {
        &self.locale
    }

    /// The End-User's ranked language tags: the matcher's `Env::priority`, over which the claims
    /// kit picks a display entry (`format_entry`) and siros-paso runs PaSO View §4's Lookup.
    #[must_use]
    pub const fn priority(&self) -> &AllOf<LocaleTag> {
        &self.priority
    }

    /// The wallet's bidi choice, which the context applies.
    #[must_use]
    pub const fn bidi(&self) -> Bidi {
        self.bidi
    }

    /// The wallet's MF2 resources for the matcher, in load order, its formats first.
    #[must_use]
    pub const fn sources(&self) -> &AllOf<String> {
        &self.sources
    }

    /// The matcher's context before a request: the sources loaded.
    #[must_use]
    pub const fn context(&self) -> &Context {
        &self.context
    }
}

/// Bases are equal when their entries are: each loads its context from them.
impl PartialEq for Base {
    fn eq(&self, other: &Self) -> bool {
        self.locale == other.locale
            && self.priority == other.priority
            && self.bidi == other.bidi
            && self.sources == other.sources
    }
}

impl Eq for Base {}

/// Why the matcher's context does not load a registration's sources.
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
    #[error("the source of the transaction type \"{kind}\" does not load")]
    #[explain(id = "context.transaction")]
    Transaction {
        /// The type.
        kind: TransactionType<'static>,
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
        /// The sources' `@locale`; `None` for a context without one.
        declared: Option<LocaleTag>,
    },
}
