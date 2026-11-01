//! Phase 1: the plan of a verified request over the wallet's usable credentials, and its consent
//! view.

mod digest;
mod proof;
mod seed;
mod transactions;
mod view;

use rand_core::CryptoRngCore;
use siros_codec::date::DateTime;
use siros_credential::{Credential, UsableCredential};
use siros_display::{CardWording, DisplayCache, Locale};
use siros_oid4vp::{ErrorCode, Submission, VerifiedRequest};
use siros_transaction_data::{Amr, Configuration, HeldMetadata, TransactionDataError};
use siros_trust::TrustStore;
use siros_wallet_state::{CredentialId, KeyId, PresentationRecord};
use siros_zkp_req_nym_auth::policy::RequestRefusal;
use siros_zkp_req_nym_auth::request::NymAuthRequest;
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use siros_zkp_req_nym_auth::verifier_id::VerifierIdForm;

use crate::display_rule::TransactionData;
use crate::error::PresentationError;
use crate::matching::{Asked, Matching};
use crate::offers::Offers;
use crate::transactions::{NoOffer, Transactions};
use transactions::{context, Wallet};
use view::Sources;

pub use digest::{DigestError, PlanDigest};
pub(crate) use proof::nym_answer;
pub use proof::{OptionRefusal, Unproven};
pub use seed::NoSeed;
pub(crate) use transactions::Offered;
pub use view::{
    AdditionView, BoundTransaction, ConsentView, CredentialView, MemberView, OfferView, Shown,
};

/// What a plan is made from. Phase 2 makes the plan again from the same input.
#[derive(Clone, Copy)]
pub struct PlanInput<'a> {
    /// The request intake verified.
    pub request: &'a VerifiedRequest,
    /// The wallet's credentials. The plan presents those usable at `now` (C4).
    pub credentials: &'a [Credential],
    /// The trust store the host provisions (H4, TR4), which resolves `trusted_authorities`.
    pub trust: &'a TrustStore,
    /// The wallet's presentation records, which choose the instance of each batch (C5).
    pub records: &'a [PresentationRecord],
    /// The display metadata the host holds.
    pub display: &'a DisplayCache,
    /// The wallet's language, which every display array is shown in (PaSO View, Section 4).
    pub language: &'a Locale,
    /// The texts the host gives cards in the wallet's language: the title and issuer line of a
    /// credential whose display metadata names none, and the template of a named issuer's line.
    pub card_wording: &'a CardWording,
    /// The transaction data types the host configures.
    pub configuration: &'a Configuration,
    /// The transaction metadata the host holds: signed credential metadata, Type Metadata and
    /// key sets.
    pub held: &'a HeldMetadata,
    /// The nym_auth systems whose circuits the host loaded, in the wallet's order of
    /// preference.
    pub systems: &'a [NymAuthSystem],
    /// The form of `verifier_id` the Verifier's trust framework fixes, for a nym_auth query.
    pub verifier_id: VerifierIdForm,
    /// The credentials the wallet declares presentable without its UI (A9).
    pub background: &'a [CredentialId],
    /// The authentication factors of each signing key the host reported (H3).
    pub key_factors: &'a [(KeyId, Amr)],
    /// The time: the proof time of a nym_auth proof and the `iat` of a KB-JWT.
    pub now: DateTime,
}

/// The plan of a request: its offers, and their consent view with its digest.
pub struct Planned<'a> {
    pub(crate) input: PlanInput<'a>,
    pub(crate) nym_auth: Result<NymAuthRequest<'a>, RequestRefusal>,
    pub(crate) answered: Wallet<'a>,
    pub(crate) transactions: Transactions,
    pub(crate) view: ConsentView<'a>,
}

/// The plan of `input` (phase 1).
///
/// The credentials usable at `now` are matched (A1, A2); a nym_auth candidate answers the first
/// option with a usable pair whose answer holds: a usable attestation at `now`, its
/// `secret_seed` from the delivered auxiliary data, and the option's assertions (N3, N4). Each
/// candidate of a query a `transaction_data` entry targets takes its first compatible entry, and
/// one with none is excluded (PaSO Core, Section 7.4.2). The offers (A3) are those of the other
/// candidates. The view shows each member's card and claim rows or verified proof statement
/// rows, and the transaction bound to it (T4).
///
/// # Errors
///
/// [`PresentationError::NoOffer`] with the reason when no offer remains, and the first rule
/// the request, its transaction data or the display breaks.
pub fn plan<'a>(input: &PlanInput<'a>) -> Result<Planned<'a>, PresentationError> {
    let request = input.request;
    let nym_auth = NymAuthRequest::new(request, input.verifier_id);
    let policy = nym_auth.as_ref().map(drop).map_err(|refusal| *refusal);
    let answered = answered(input, policy)?;
    let transactions = Transactions::read(request, &answered, &context(input))?;
    let offers = offers(&answered, &transactions)?;
    let sources = Sources {
        answered: &answered,
        transactions: &transactions,
        display: input.display,
        language: input.language,
        card_wording: input.card_wording,
        background: input.background,
        transaction_data: TransactionData::of(&transactions),
    };
    let views = view::offer_views(&offers, &sources)?;
    // A request that is no nym_auth request has no `verifier_id`.
    let verifier_id = nym_auth
        .as_ref()
        .ok()
        .map(|nym_auth| &nym_auth.session().verifier_id);
    let digest = PlanDigest::of(request, verifier_id, &views);
    let view = ConsentView::new(request.verifier(), digest, views, offers.unexamined());
    Ok(Planned {
        input: *input,
        nym_auth,
        answered,
        transactions,
        view,
    })
}

/// The candidates of each Credential Query of `input`'s request, over the credentials usable at
/// `now` (C4) whose issuer the query's `trusted_authorities` admit against the trust store at
/// `now` (TR3). Each `zkp_req` candidate answers the first option its tests pass; `policy` says
/// whether the request meets the nym_auth policy.
///
/// # Errors
///
/// [`PresentationError::NoOffer`] when a Credential Query makes the request invalid.
fn answered<'a>(
    input: &PlanInput<'a>,
    policy: Result<(), RequestRefusal>,
) -> Result<Wallet<'a>, PresentationError> {
    let request = input.request;
    let asked = Asked::of(request);
    let usable: Vec<UsableCredential<'a>> = input
        .credentials
        .iter()
        .filter_map(|credential| UsableCredential::at(credential, input.now).ok())
        .collect();
    let matching = Matching::new(
        asked,
        &usable,
        input.trust,
        input.records,
        input.systems,
        input.now.date(),
        policy,
    );
    let answered = matching.answer(|credential, issuer, zkp| {
        proof::first_answered(credential, issuer, zkp, input.now)
    });
    match answered.invalid_request() {
        Some(failure) => Err(failure.into()),
        None => Ok(answered),
    }
}

/// The offers of `answered` over the candidates the first match of `transactions` leaves.
///
/// # Errors
///
/// [`PresentationError`] when no offer remains:
/// [`TransactionDataError::CredentialUnavailable`] when the queries the entries target have no
/// candidate, else why the request has no offer.
fn offers(answered: &Wallet<'_>, transactions: &Transactions) -> Result<Offers, PresentationError> {
    transactions
        .offers(answered)
        .map_err(|no_offer| match no_offer {
            NoOffer::CredentialUnavailable => TransactionDataError::CredentialUnavailable.into(),
            NoOffer::Unmatched(failure) => failure.into(),
        })
}

impl<'a> Planned<'a> {
    /// The consent view.
    pub fn view(&self) -> &ConsentView<'a> {
        &self.view
    }

    /// The submission of the user's decline: `access_denied` (A8).
    ///
    /// # Errors
    ///
    /// [`PresentationError::Response`] when the error response cannot be encrypted.
    pub fn decline(&self, rng: &mut impl CryptoRngCore) -> Result<Submission, PresentationError> {
        refusal(self.input.request, ErrorCode::AccessDenied, rng)
    }
}

/// The submission refusing `request` with `code`, an error's
/// [`PresentationError::error_code`] (P5: the response target of a verified request is
/// verified).
///
/// # Errors
///
/// [`PresentationError::Response`] when the error response cannot be encrypted.
pub fn refusal(
    request: &VerifiedRequest,
    code: ErrorCode,
    rng: &mut impl CryptoRngCore,
) -> Result<Submission, PresentationError> {
    Ok(request.error_submission(code, rng)?)
}
