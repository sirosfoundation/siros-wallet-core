//! The rules the QES profile adds to a request's, and the exclusions it gives.

use std::borrow::Cow;
use std::fmt;

use siros_explain::{AllOf, Explain, IntoArg, Listed, kind};
use siros_openid4vp::plugins::Exclusion;
use siros_openid4vp::refusal::{ErrorCode, RequestRule};

use crate::approval::Problem;

/// A rule a QES entry breaks: `invalid_transaction_data`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "qes.rules")]
pub enum QesRule {
    /// An entry breaks the type's rules (CSC §7.1).
    #[error("QES entry {entry}: {problem}")]
    Entry {
        /// The entry's position.
        entry: usize,
        /// The rule it breaks.
        problem: Problem,
    },
    /// Two entries name one query: one presentation approves one request.
    #[error("QES entries {entries} name {query}: one presentation approves one request")]
    OneRequest {
        /// The entries' positions.
        entries: Positions,
        /// The query's id.
        query: String,
    },
}

/// The positions of the entries a rule names: the list `[1, 2]` in its text, an and-list in its
/// message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Positions(AllOf<usize>);

impl Positions {
    /// The positions, in their order.
    #[must_use]
    pub const fn new(entries: AllOf<usize>) -> Self {
        Self(entries)
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
        ErrorCode::InvalidTransactionData
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
        qualifier: &'static str,
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
