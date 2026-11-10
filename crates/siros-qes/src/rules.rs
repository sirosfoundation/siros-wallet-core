//! The rules the QES profile adds to a request's, and the exclusions it gives.

use std::fmt;

use siros_explain::Explain;
use siros_openid4vp::plugins::{Clause, Exclusion};
use siros_openid4vp::refusal::{ErrorCode, RequestRule};
use siros_openid4vp::request::EntryIndex;
use siros_syntax::AllOf;

use crate::approval::{DocumentNumber, Problem, SignatureQualifier};

/// A rule a QES entry breaks: `invalid_transaction_data`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum QesRule {
    /// An entry breaks the type's rules (CSC §7.1).
    #[error("QES entry {entry}: {problem}")]
    #[explain(id = "rules.entry")]
    Entry {
        /// The entry.
        entry: EntryPosition,
        /// The rule it breaks.
        #[source]
        problem: Problem,
    },
    /// Two entries name one query: one presentation approves one request.
    #[error("QES entries {entries} name {query}: one presentation approves one request")]
    #[explain(id = "rules.one_request")]
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

/// The positions of the entries a rule names, written as the list `[1, 2]`.
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

impl RequestRule for QesRule {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_TRANSACTION_DATA
    }
}

/// Why the QES profile excludes a credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum Excluded {
    /// The credential's rulebook does not let it approve the qualifier.
    #[error("the credential cannot approve {qualifier}")]
    #[explain(id = "excluded.qualifier")]
    Qualifier {
        /// The `signatureQualifier`.
        qualifier: SignatureQualifier,
    },
    /// The presentation cannot carry `qesApproval`.
    #[error("the presentation cannot carry qesApproval")]
    #[explain(id = "excluded.carriage")]
    Carriage,
    /// A linked document fails its checksum.
    #[error("document {document} does not match its checksum")]
    #[explain(id = "excluded.checksum")]
    Checksum {
        /// The document.
        document: DocumentNumber,
    },
}

impl Exclusion for Excluded {
    fn clause(&self) -> Clause {
        Clause::cited(match self {
            Self::Qualifier { .. } => "CSC §6.3; §7.2.1 Note 22",
            Self::Carriage => "CSC §7.2.1; OpenID4VP B.2",
            Self::Checksum { .. } => "CSC §6.3",
        })
    }
}
