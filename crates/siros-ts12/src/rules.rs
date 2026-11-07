//! The request rules T1 to T6 (section 4.10.2) and what excludes a credential in phase 1.

use siros_explain::Explain;
use siros_openid4vp::hash::{self, HashesAlgRule};
use siros_openid4vp::plugins::{Clause, Exclusion};
use siros_openid4vp::refusal::{ErrorCode, Refusal, RequestRule};
use siros_openid4vp::request::{EntryIndex, Multiplicity, Request};
use siros_paso::entry::Payload;
use siros_paso::outcome::Outcome;

use crate::document::Ts12Type;
use crate::payload::PayloadRefusal;
use crate::translate::Ts12Unsupported;

/// A rule TS12 and CS-12 set on a request over its TS12 entries.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "ts12.rule")]
pub enum Ts12Rule {
    /// T1: an entry without `transaction_data_hashes_alg` (TS12 §4.2).
    #[error("entry {entry}: no transaction_data_hashes_alg")]
    NoHashes {
        /// The entry's position.
        entry: usize,
    },
    /// T1: an entry without a `payload` object (TS12 §4.2).
    #[error("entry {entry}: no payload object")]
    NoPayload {
        /// The entry's position.
        entry: usize,
    },
    /// T2: a second TS12 entry (CS-12 §8.1).
    #[error("entry {entry}: a second entry under urn:eudi:sca:")]
    Second {
        /// The entry's position.
        entry: usize,
    },
    /// T3: `credential_ids` holding more than one id (CS-12 §8.1, §7.3 item 7).
    #[error("entry {entry}: credential_ids holds more than one id")]
    CredentialIds {
        /// The entry's position.
        entry: usize,
    },
    /// T4: a type other than the two served (CS-12 §7.1 item 1, §7.3 item 10).
    #[error("entry {entry}: {kind} is no type this profile serves")]
    Type {
        /// The entry's position.
        entry: usize,
        /// The type.
        kind: String,
    },
    /// T5: an unsigned request carrying a TS12 entry (CS-12 §7.3 item 3; PaSO Core §3).
    #[error("a TS12 entry in an unsigned request")]
    Unsigned,
    /// T6: `multiple` true on the query a TS12 entry names (CS-12 §8.1).
    #[error("query {query}: multiple is true on the query a TS12 entry names")]
    Multiple {
        /// The query's id.
        query: String,
    },
    /// OpenID4VP B.3.3.1's rule over the entry's `transaction_data_hashes_alg`.
    #[error("entry {entry}: {rule}")]
    Hashes {
        /// The entry's position.
        entry: usize,
        /// The rule.
        rule: HashesAlgRule,
    },
}

impl RequestRule for Ts12Rule {
    fn code(&self) -> ErrorCode {
        match self {
            Self::NoHashes { .. }
            | Self::NoPayload { .. }
            | Self::Second { .. }
            | Self::CredentialIds { .. }
            | Self::Type { .. } => ErrorCode::INVALID_TRANSACTION_DATA,
            Self::Unsigned | Self::Multiple { .. } => ErrorCode::INVALID_REQUEST,
            Self::Hashes { rule, .. } => rule.code(),
        }
    }
}

/// The rules a request breaks over its TS12 entries, in the order T5, each entry's, T6.
pub(crate) fn refusals(request: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal> {
    let mut out = Vec::new();
    if request.request_object().is_none() {
        out.push(Refusal::new(Ts12Rule::Unsigned));
    }
    let hashes = request.envelope().hashes();
    let own = request
        .indexed_entries()
        .filter(|(index, _)| entries.contains(index));
    for (position, (index, entry)) in own.enumerate() {
        let at = index.get();
        let members = entry.members();
        if position > 0 {
            out.push(Refusal::new(Ts12Rule::Second { entry: at }));
        }
        if members.get("transaction_data_hashes_alg").is_none() {
            out.push(Refusal::new(Ts12Rule::NoHashes { entry: at }));
        }
        if members.get("payload").and_then(Payload::of).is_none() {
            out.push(Refusal::new(Ts12Rule::NoPayload { entry: at }));
        }
        if entry.credential_ids().len() > 1 {
            out.push(Refusal::new(Ts12Rule::CredentialIds { entry: at }));
        }
        let kind = entry.kind().as_str();
        if Ts12Type::of(kind).is_none() {
            out.push(Refusal::new(Ts12Rule::Type {
                entry: at,
                kind: kind.to_owned(),
            }));
        }
        out.extend(
            hash::rule(entry, hashes)
                .map(|rule| Refusal::new(Ts12Rule::Hashes { entry: at, rule })),
        );
        out.extend(
            request
                .queries()
                .iter()
                .filter(|query| {
                    query.multiple() == Multiplicity::Many
                        && entry
                            .credential_ids()
                            .iter()
                            .any(|id| id.as_str() == query.id().as_str())
                })
                .map(|query| {
                    Refusal::new(Ts12Rule::Multiple {
                        query: query.id().as_str().to_owned(),
                    })
                }),
        );
    }
    out
}

/// Why phase 1 excludes a credential, beyond View §4's locale rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "ts12.excluded")]
pub enum Ts12Excluded {
    /// The presentation cannot carry TS12's Key Binding JWT claims.
    #[error("its presentation cannot carry TS12's claims")]
    Carriage,
    /// The type is unsupported for the credential (phase 1's steps 1 to 4).
    #[error(transparent)]
    Unsupported(#[from] Ts12Unsupported),
    /// The payload breaks a rule of its field table (step 5).
    #[error(transparent)]
    Payload(#[from] PayloadRefusal),
    /// siros-paso's engine refuses the translation (step 6).
    #[error(transparent)]
    Rendering(#[from] Outcome),
}

impl Exclusion for Ts12Excluded {
    fn clause(&self) -> Clause {
        match self {
            Self::Carriage => Clause::cited("TS12 §1.2, §3.6"),
            Self::Unsupported(_) => Clause::cited("TS12 §3.2, §3.3.1"),
            Self::Payload(_) => Clause::cited("TS12 §4.3"),
            Self::Rendering(outcome) => outcome.clause(),
        }
    }
}
