//! The linked documents' integrity (CSC §6.3): what a fetch of a document returned, its check
//! against the document's checksum, and what phase 2 finds when a check fails.

use siros_openid4vp::sri;

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

/// A linked document whose integrity check failed: its `href`, and what its fetch returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedDocument {
    /// The URI.
    pub href: String,
    /// What the fetch returned: content that does not match the checksum, or nothing.
    pub fetched: Fetched,
}

/// What phase 2 finds: the linked documents of the entry whose integrity check failed, at least
/// one, in the entry's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedDocuments(Vec<FailedDocument>);

impl FailedDocuments {
    siros_openid4vp::with_resolve! {
        /// The finding of the failed documents; `None` when none failed.
        pub(crate) fn of(failed: Vec<FailedDocument>) -> Option<Self> {
            (!failed.is_empty()).then_some(Self(failed))
        }
    }

    /// The failed documents in the entry's order.
    #[must_use]
    pub fn documents(&self) -> &[FailedDocument] {
        &self.0
    }
}
