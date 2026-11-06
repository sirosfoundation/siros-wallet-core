//! The linked documents' integrity (CSC §6.3): what a fetch of a document returned, its check
//! against the document's checksum, and what phase 2 finds when a check fails.

use std::borrow::Borrow;

use siros_explain::AllOf;
use siros_openid4vp::sri;

/// A linked document's `href` as its entry writes it: any text, https or `data:` included (CSC
/// §6.2.1), compared byte for byte.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DocumentHref(String);

impl DocumentHref {
    /// The `href` of that text.
    #[must_use]
    pub fn new(href: &str) -> Self {
        Self(href.to_owned())
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for DocumentHref {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// What fetching a linked document returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// The content.
    Content(Vec<u8>),
    /// The fetch failed.
    Failed,
}

impl Fetched {
    /// Whether the content matches the checksum (W3C SRI metadata); a failed fetch matches none.
    pub(crate) fn verifies(&self, checksum: &str) -> bool {
        match self {
            Self::Content(content) => sri::matches(content, checksum),
            Self::Failed => false,
        }
    }
}

/// A linked document whose integrity check failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedDocument {
    href: DocumentHref,
    fetched: Fetched,
}

impl FailedDocument {
    #[cfg(feature = "resolve")]
    pub(crate) const fn new(href: DocumentHref, fetched: Fetched) -> Self {
        Self { href, fetched }
    }

    /// The document's link.
    #[must_use]
    pub const fn href(&self) -> &DocumentHref {
        &self.href
    }

    /// What the fetch returned: content that does not match the checksum, or nothing.
    #[must_use]
    pub const fn fetched(&self) -> &Fetched {
        &self.fetched
    }
}

/// What phase 2 finds: the linked documents of the entry whose integrity check failed, at least
/// one, in the entry's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedDocuments(AllOf<FailedDocument>);

impl FailedDocuments {
    #[cfg(feature = "resolve")]
    /// The finding of the failed documents; `None` when none failed.
    pub(crate) fn of(failed: Vec<FailedDocument>) -> Option<Self> {
        AllOf::new(failed).map(Self)
    }

    /// The failed documents in the entry's order.
    #[must_use]
    pub fn documents(&self) -> &[FailedDocument] {
        self.0.items()
    }
}
