//! The wallet's tests of a nym_auth candidate (A2; N3, N4): a usable attestation at the proof
//! time, the `secret_seed` its issuer delivered, and an option it answers.

use itertools::Itertools;
use siros_codec::date::DateTime;
use siros_credential::{Parsed, UsableCredential};
use siros_trust::AdmittedIssuer;
use siros_zkp_req_nym_auth::attestation::{
    OtherIssuer, SecretSeed, TestedAttestation, Unreadable, Unusable, UsableAttestation,
};
use siros_zkp_req_nym_auth::outcome::CredentialCode;
use siros_zkp_req_nym_auth::presenter::{Answer as NymAnswer, Unanswerable};

use super::seed::{self, NoSeed};
use crate::error::PresentationError;
use crate::matching::{ChoiceError, ProofChoice, ZkpQuery};

/// Why a nym_auth candidate answers no option of its query.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum Unproven {
    /// The credential is no mdoc.
    NotAnMdoc,
    /// The mdoc is of another `docType`.
    OtherDocType,
    /// The credential cannot be read in the nym_auth form: `credential_form`.
    Unreadable(#[source] Unreadable),
    /// The admission of the credential's issuer is for another certificate or query.
    Issuer(#[from] OtherIssuer),
    /// The credential fails these tests at the proof time.
    Fails(Vec<CredentialCode>),
    /// The issuer delivered no usable `secret_seed`.
    Seed(#[from] NoSeed),
    /// Each option with a usable pair refuses the credential, in the Verifier's order.
    Options(Vec<OptionRefusal>),
}

/// Why an option of a nym_auth query refuses a credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OptionRefusal {
    /// The option's pair is not usable again.
    #[error("the option's pair is not usable again")]
    Choice(#[source] ChoiceError),
    /// An item of the option fails for the credential.
    #[error("an item of the option fails for the credential")]
    Unanswerable(#[source] Unanswerable),
}

impl Unproven {
    /// A stable identifier: the code of the test that failed, `credential` for several, or
    /// `no_option_answered`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotAnMdoc => "not_an_mdoc",
            Self::OtherDocType => "other_doc_type",
            Self::Unreadable(_) => CredentialCode::CredentialForm.code(),
            Self::Issuer(e) => e.code(),
            Self::Fails(_) => "credential",
            Self::Seed(e) => e.code(),
            Self::Options(_) => "no_option_answered",
        }
    }
}

impl From<Unusable> for Unproven {
    fn from(unusable: Unusable) -> Self {
        match unusable {
            Unusable::OtherDocType => Self::OtherDocType,
            Unusable::Unreadable(unreadable) => Self::Unreadable(unreadable),
            Unusable::Fails(failures) => Self::Fails(failures.codes().to_vec()),
        }
    }
}

/// The first of `zkp`'s choices `credential`, whose issuer `issuer` admits, answers at `now`, in
/// the Verifier's order.
///
/// # Errors
///
/// [`Unproven`]: the credential's failed tests, its seed, or the refusal of every option.
pub(super) fn first_answered(
    credential: &UsableCredential<'_>,
    issuer: &AdmittedIssuer,
    zkp: &ZkpQuery,
    now: DateTime,
) -> Result<ProofChoice, Unproven> {
    let (attestation, seed) = tested(credential, issuer, zkp, now)?;
    let (answered, refusals): (Vec<ProofChoice>, Vec<OptionRefusal>) = zkp
        .choices()
        .iter()
        .map(|choice| {
            let pair = zkp.pair(choice).map_err(OptionRefusal::Choice)?;
            NymAnswer::new(pair, attestation.clone(), &seed)
                .map(|_answer| choice.clone())
                .map_err(OptionRefusal::Unanswerable)
        })
        .partition_result();
    answered
        .into_iter()
        .next()
        .ok_or(Unproven::Options(refusals))
}

/// The answer of `choice` by `credential`, whose issuer `issuer` admits, at `now`, which opens
/// the attestation's `ssc` again for this use.
///
/// # Errors
///
/// [`PresentationError`]: the credential's failed tests or seed, a choice that gives no usable
/// pair, or an item of the option that fails.
pub(crate) fn nym_answer<'z>(
    credential: &UsableCredential<'_>,
    issuer: &AdmittedIssuer,
    zkp: &'z ZkpQuery,
    choice: &ProofChoice,
    now: DateTime,
) -> Result<NymAnswer<'z>, PresentationError> {
    let (attestation, seed) = tested(credential, issuer, zkp, now)?;
    Ok(NymAnswer::new(zkp.pair(choice)?, attestation, &seed)?)
}

/// The attestation of `credential`'s mdoc tested at `now`, usable for `zkp` because `issuer`
/// admits its Document Signer, and the `secret_seed` its issuer delivered.
fn tested(
    credential: &UsableCredential<'_>,
    issuer: &AdmittedIssuer,
    zkp: &ZkpQuery,
    now: DateTime,
) -> Result<(UsableAttestation, SecretSeed), Unproven> {
    let Parsed::Mdoc(mdoc) = credential.credential().parsed() else {
        return Err(Unproven::NotAnMdoc);
    };
    let tested = TestedAttestation::of(mdoc, now)?;
    let attestation = UsableAttestation::new(tested, issuer.clone(), zkp.query())?;
    let seed = seed::delivered(credential.credential())?;
    Ok((attestation, seed))
}
