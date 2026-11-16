//! Transaction data in the plan (PaSO Core, Section 7.4): the wallet's sources.

use std::convert::Infallible;

use siros_credential::UsableCredential;
use siros_transaction_data::{Context, Entry, Selection, SourceInputs, TransactionDataError};

use super::{PlanInput, Unproven};
use crate::matching::Answered;
use crate::request::MatchRequest;
use crate::transactions::TransactionSource;

/// The answers of a request over the wallet's usable credentials.
pub(crate) type Wallet<'a> = Answered<'a, UsableCredential<'a>, Unproven>;

/// The wallet's sources: the credential's own metadata, the configuration and the entry's ad-hoc
/// metadata, verified against the trust store and what the host holds.
impl<'a> TransactionSource<UsableCredential<'a>> for Context<'a> {
    type Deferral = Infallible;

    fn first_match(
        &self,
        entries: &[&Entry],
        credential: &UsableCredential<'a>,
    ) -> Result<Selection, TransactionDataError> {
        Context::first_match(self, entries, credential.credential())
    }

    fn knows(&self, entry: &Entry, credential: &UsableCredential<'a>) -> bool {
        Context::knows(self, entry, credential.credential())
    }
}

/// The context of `input`'s transaction data: the trust store, the metadata and display the
/// host holds, the configuration, the wallet's language, the time, and how the request reached
/// the wallet.
pub(crate) fn context<'a>(input: &PlanInput<'a>) -> Context<'a> {
    Context {
        sources: SourceInputs {
            trust: input.trust,
            held: input.held,
            display: input.display,
            configuration: input.configuration,
            language: input.language,
            now: input.now,
        },
        channel: input.request.channel(),
        signature: input.request.signature(),
    }
}

/// A member of an offer as the matching answers it over the wallet's usable credentials.
pub(crate) type Offered<'w, 'a> =
    crate::transactions::Offered<'w, 'a, UsableCredential<'a>, Unproven>;
