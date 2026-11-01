//! The answer of an option: a usable pair, a usable attestation and the seed that opens it, for
//! which every item of the option holds (system rulebooks, Section 7, step 1).

use crate::attestation::{Credential, OpenedSeed, SecretSeed, SeedMismatch, UsableAttestation};
use crate::outcome::{ItemCode, ZkpError};
use crate::pair::{failed_assertions, UsablePair};

/// What the proof of an option needs: a usable pair for it, an attestation usable for its query
/// at the pair's proof date, and the `secret_seed` that opens the attestation's `ssc`. Every
/// assertion of the option holds for the attestation.
#[derive(Debug, Clone)]
pub struct Answer<'q> {
    pair: UsablePair<'q>,
    attestation: UsableAttestation,
    seed: OpenedSeed,
}

/// Why an attestation does not answer an option.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum Unanswerable {
    /// The attestation is usable for the authorities of another query than the pair's: another
    /// `id`, or other `trusted_authorities`.
    OtherQuery,
    /// The attestation was tested at another date than the pair's proof date.
    ProofDate,
    /// Items of the option fail for the attestation: an assertion, or the `pseudonym`'s seed.
    Failed(Vec<ZkpError>),
}

impl Unanswerable {
    /// A stable identifier: `other_query`, `proof_date`, or `credential` for failed items, with
    /// their codes in the variant.
    pub fn code(&self) -> &'static str {
        match self {
            Self::OtherQuery => "other_query",
            Self::ProofDate => "proof_date",
            Self::Failed(_) => "credential",
        }
    }
}

impl<'q> Answer<'q> {
    /// The answer of `pair`'s option by `attestation`, whose `ssc` `secret_seed` opens. The
    /// seed is opened again here, for this use (privatedata, Section 5A.2).
    ///
    /// # Errors
    ///
    /// [`Unanswerable::OtherQuery`] for an attestation usable for the authorities of another
    /// query, [`Unanswerable::ProofDate`] for one tested at another date than the pair's, and
    /// [`Unanswerable::Failed`] with the `age_check` that fails and `seed_mismatch` for a seed
    /// that does not open `ssc`.
    pub fn new(
        pair: UsablePair<'q>,
        attestation: UsableAttestation,
        secret_seed: &SecretSeed,
    ) -> Result<Self, Unanswerable> {
        let query = pair.option().query().query().credential_query();
        if !attestation.issuer().authorities().are_those_of(query) {
            return Err(Unanswerable::OtherQuery);
        }
        if attestation.proof_time().date() != pair.date() {
            return Err(Unanswerable::ProofDate);
        }
        let seed = opened_seed(&pair, attestation.credential(), secret_seed)
            .map_err(Unanswerable::Failed)?;
        Ok(Self {
            pair,
            attestation,
            seed,
        })
    }

    /// The usable pair.
    pub fn pair(&self) -> &UsablePair<'q> {
        &self.pair
    }

    /// The usable attestation.
    pub fn attestation(&self) -> &UsableAttestation {
        &self.attestation
    }

    pub(crate) fn into_parts(self) -> (UsablePair<'q>, UsableAttestation, OpenedSeed) {
        (self.pair, self.attestation, self.seed)
    }
}

/// The seed that opens `credential`'s `ssc` when every item of `pair`'s option holds for it.
///
/// # Errors
///
/// The items that fail: the `age_check` assertion, then the `pseudonym` whose `secret_seed`
/// does not open `ssc`.
fn opened_seed(
    pair: &UsablePair<'_>,
    credential: &Credential,
    secret_seed: &SecretSeed,
) -> Result<OpenedSeed, Vec<ZkpError>> {
    let option = pair.option();
    let birth_date = *credential.mdoc().birth_date().value();
    let assertions = failed_assertions(option.query(), option.option(), pair.bounds(), birth_date);
    match OpenedSeed::open(credential, secret_seed) {
        Ok(seed) if assertions.is_empty() => Ok(seed),
        Ok(_) => Err(assertions),
        Err(SeedMismatch) => {
            let seed = ZkpError::Item {
                option: option.option().req_set(),
                item: pair.pseudonym().index,
                code: ItemCode::SeedMismatch,
            };
            Err(assertions.into_iter().chain([seed]).collect())
        }
    }
}
