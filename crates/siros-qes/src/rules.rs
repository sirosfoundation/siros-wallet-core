//! The rules the QES profile adds to a request's, and the exclusions it gives.

use std::borrow::Cow;
use std::fmt;

use siros_explain::{AllOf, Count, Explain, IntoArg, Listed, kind};
use siros_openid4vp::plugins::Exclusion;
use siros_openid4vp::refusal::{ErrorCode, RequestRule};
use siros_openid4vp::request::EntryIndex;

use crate::approval::{Problem, SignatureQualifier};

/// A rule a QES entry breaks: `invalid_transaction_data`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "qes.rules")]
pub enum QesRule {
    /// An entry breaks the type's rules (CSC §7.1).
    #[error("QES entry {entry}: {problem}")]
    Entry {
        /// The entry.
        entry: EntryPosition,
        /// The rule it breaks.
        problem: Problem,
    },
    /// Two entries name one query: one presentation approves one request.
    #[error("QES entries {entries} name {query}: one presentation approves one request")]
    OneRequest {
        /// The entries.
        entries: Positions,
        /// The query's id, as the entries write it.
        query: String,
    },
}

/// An entry's position in `transaction_data`, as a rule names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryPosition(EntryIndex);

impl EntryPosition {
    pub(crate) const fn of(entry: EntryIndex) -> Self {
        Self(entry)
    }

    /// The position.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

impl fmt::Display for EntryPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

impl IntoArg for EntryPosition {
    type Kind = kind::Count;

    fn arg(&self) -> Count {
        self.get().arg()
    }
}

/// The positions of the entries a rule names: the list `[1, 2]` in its text, an and-list in its
/// message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Positions(AllOf<EntryPosition>);

impl Positions {
    pub(crate) const fn new(entries: AllOf<EntryPosition>) -> Self {
        Self(entries)
    }

    /// The positions, in their order.
    #[must_use]
    pub fn entries(&self) -> &[EntryPosition] {
        self.0.items()
    }
}

impl fmt::Display for Positions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (k, entry) in self.0.items().iter().enumerate() {
            if k > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{entry}")?;
        }
        f.write_str("]")
    }
}

impl IntoArg for Positions {
    type Kind = kind::List;

    fn arg(&self) -> Listed<'_> {
        self.0.arg()
    }
}

impl RequestRule for QesRule {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_TRANSACTION_DATA
    }
}

/// Why the QES profile excludes a credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "qes.excluded")]
pub enum Excluded {
    /// The credential's rulebook does not let it approve the qualifier.
    #[error("the credential cannot approve {qualifier}")]
    Qualifier {
        /// The `signatureQualifier`.
        qualifier: SignatureQualifier,
    },
    /// The presentation cannot carry `qesApproval`.
    #[error("the presentation cannot carry qesApproval")]
    Carriage,
    /// A linked document fails its checksum.
    #[error("document {document} does not match its checksum")]
    Checksum {
        /// The document's position.
        document: usize,
    },
}

impl Exclusion for Excluded {
    fn clause(&self) -> Cow<'static, str> {
        Cow::Borrowed(match self {
            Self::Qualifier { .. } => "CSC §6.3; §7.2.1 Note 22",
            Self::Carriage => "CSC §7.2.1; OpenID4VP B.2",
            Self::Checksum { .. } => "CSC §6.3",
        })
    }
}
