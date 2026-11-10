//! The rules PaSO adds to a request's, and the exclusions its binding gives.

use std::fmt;

use siros_explain::Explain;
use siros_openid4vp::plugins::{Clause, Exclusion};
use siros_openid4vp::refusal::{ErrorCode, RequestRule};
use siros_openid4vp::request::EntryIndex;

use crate::entry::EntryRule;
use crate::outcome::Excluded;

/// A rule PaSO sets on a request over its own entries.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum PasoRule {
    /// Core §3: the request is unsigned.
    #[error("PaSO requests are signed; this one is not (Core §3)")]
    #[explain(id = "rules.unsigned")]
    Unsigned,
    /// An entry's members break a rule.
    #[error("PaSO entry {entry}: {rule}")]
    #[explain(id = "rules.entry")]
    Entry {
        /// The entry.
        entry: EntryPosition,
        /// The rule.
        #[source]
        rule: EntryRule,
    },
    /// Core §7.4.1: the alternatives involving the entries' queries are not transposable.
    #[error("PaSO alternatives involving its transaction data are not transposable (Core §7.4.1)")]
    #[explain(id = "rules.coupled")]
    Coupled,
    /// Core §7.4.1: the entries' queries sit in more than one credential set.
    #[error("PaSO transaction data names queries of more than one credential set (Core §7.4.1)")]
    #[explain(id = "rules.sets")]
    Sets,
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

impl RequestRule for PasoRule {
    fn code(&self) -> ErrorCode {
        match self {
            Self::Unsigned => ErrorCode::INVALID_REQUEST,
            Self::Entry { .. } | Self::Coupled | Self::Sets => ErrorCode::INVALID_TRANSACTION_DATA,
        }
    }
}

/// Why PaSO's binding excludes a credential, beyond View §4's locale rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
pub enum BindExcluded {
    /// The presentation cannot carry the SCA response claims.
    #[error("its presentation cannot carry the SCA response claims")]
    #[explain(id = "excluded.carriage")]
    Carriage,
    /// No entry renders for the credential.
    #[error("no PaSO entry is compatible with the credential")]
    #[explain(id = "excluded.no_entry")]
    NoEntry,
}

impl Exclusion for BindExcluded {
    fn clause(&self) -> Clause {
        Clause::cited(match self {
            Self::Carriage => "Core §6; OpenID4VP B.2",
            Self::NoEntry => "Core §7.4.2 step 2",
        })
    }
}

impl Exclusion for Excluded {
    fn clause(&self) -> Clause {
        Excluded::clause(self)
    }
}
