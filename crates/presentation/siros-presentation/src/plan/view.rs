//! The consent view: the verifier, and per offer its purposes, its credentials with their
//! claim or proof statement rows, its additions and its transactions.

use siros_credential::EntryRef;
use siros_dcql::Dropped;
use siros_display::proof::{self, verified_rows, ProofRow};
use siros_display::{purpose, Card, CardWording, ClaimRow, DisplayCache, Field, Locale};
use siros_oid4vp::VerifierView;
use siros_transaction_data::{EntryPosition, TransactionView};
use siros_wallet_state::CredentialId;

use super::digest::PlanDigest;
use super::transactions::{Offered, Wallet};
use crate::display_rule::{
    Choice, DisplayFacts, HostDisplay, Presentability, Rows, TransactionData, WalletDisplay,
};
use crate::error::PresentationError;
use crate::ids::SetIndex;
use crate::inconsistency::Inconsistency;
use crate::matching::{Answer, Candidate};
use crate::offers::{Addition, Member, Offer, Offers};
use crate::transactions::Transactions;
use crate::transactions::{offered, Bound, BoundEntry};
use siros_dcql::QueryId;

/// What the user consents to. It holds no delivered secret and no undisclosable attribute.
pub struct ConsentView<'a> {
    verifier: VerifierView<'a>,
    digest: PlanDigest,
    offers: Vec<OfferView>,
    unexamined: Dropped,
}

/// An offer as the user sees it.
pub struct OfferView {
    offer: Offer,
    purpose: Option<String>,
    members: Vec<MemberView>,
    additions: Vec<AdditionView>,
    unexamined: Dropped,
    facts: DisplayFacts,
}

/// An addition as the user sees it.
pub struct AdditionView {
    set: SetIndex,
    purpose: Option<String>,
    members: Vec<MemberView>,
}

/// A member of an offer as the user sees it: its Credential Query and its credentials, one
/// unless the query sets `multiple`.
pub struct MemberView {
    query_id: QueryId,
    credentials: Vec<CredentialView>,
}

/// A credential of a member as the user sees it.
pub struct CredentialView {
    entry: EntryRef,
    answer: Answer,
    card: Card,
    shown: Shown,
    fields: Vec<Field>,
    transaction: Option<BoundTransaction>,
}

/// The transaction entry bound to a credential (T4): its position in the request's
/// `transaction_data`, and its display.
pub struct BoundTransaction {
    entry: EntryPosition,
    view: TransactionView,
}

impl BoundTransaction {
    /// The entry's position in the request's `transaction_data`.
    pub fn entry(&self) -> EntryPosition {
        self.entry
    }

    /// The entry's display.
    pub fn view(&self) -> &TransactionView {
        &self.view
    }
}

/// What a member shows of its credential.
pub enum Shown {
    /// The rows of the claims it discloses.
    Claims(Vec<ClaimRow>),
    /// The proof statement rows of the `zkp_req` option it answers.
    Proof(Vec<ProofRow>),
}

impl<'a> ConsentView<'a> {
    /// The view of the request of `verifier`, whose offers show as `offers`, with the plan's
    /// `digest`.
    pub(crate) fn new(
        verifier: VerifierView<'a>,
        digest: PlanDigest,
        offers: Vec<OfferView>,
        unexamined: Dropped,
    ) -> Self {
        Self {
            verifier,
            digest,
            offers,
            unexamined,
        }
    }

    /// Who asks.
    pub fn verifier(&self) -> VerifierView<'a> {
        self.verifier
    }

    /// The plan's digest, which the selection returns (A4).
    pub fn digest(&self) -> &PlanDigest {
        &self.digest
    }

    /// The offers, in the plan's order.
    pub fn offers(&self) -> &[OfferView] {
        &self.offers
    }

    /// How many combinations were not examined for offers.
    pub fn unexamined(&self) -> Dropped {
        self.unexamined
    }
}

impl OfferView {
    /// The offer of the plan the view shows.
    pub(crate) fn offer(&self) -> &Offer {
        &self.offer
    }

    /// The `purpose` of the credential sets the offer satisfies, as one line.
    pub fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }

    /// The credentials.
    pub fn members(&self) -> &[MemberView] {
        &self.members
    }

    /// The additions the user may choose.
    pub fn additions(&self) -> &[AdditionView] {
        &self.additions
    }

    /// How many combinations of the optional sets were not examined for additions.
    pub fn unexamined(&self) -> Dropped {
        self.unexamined
    }

    /// Whether the offer needs the wallet's display (A9), the host showing everything its
    /// entries carry.
    pub fn wallet_display(&self) -> WalletDisplay {
        WalletDisplay::of(&self.facts)
    }

    /// What A9 judges the offer by, the host showing everything its entries carry.
    pub(crate) fn facts(&self) -> DisplayFacts {
        self.facts
    }
}

impl AdditionView {
    /// The position of the addition's credential set in `credential_sets`.
    pub fn set(&self) -> SetIndex {
        self.set
    }

    /// The purpose of the addition's credential set.
    pub fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }

    /// The credentials.
    pub fn members(&self) -> &[MemberView] {
        &self.members
    }
}

impl MemberView {
    /// The Credential Query the member answers.
    pub fn query_id(&self) -> &QueryId {
        &self.query_id
    }

    /// The credentials, in the order of the member's candidates. For a `multiple` query, the
    /// selection chooses a subset of them by `credentialId`.
    pub fn credentials(&self) -> &[CredentialView] {
        &self.credentials
    }
}

impl CredentialView {
    /// The instance presented. A selection names it by its `credentialId`; the entries bound
    /// to it name it by `credentialId` and instance (T4).
    pub fn entry(&self) -> EntryRef {
        self.entry
    }

    /// What the instance presents.
    pub(crate) fn answer(&self) -> &Answer {
        &self.answer
    }

    /// The credential's card.
    pub fn card(&self) -> &Card {
        &self.card
    }

    /// What the credential shows.
    pub fn shown(&self) -> &Shown {
        &self.shown
    }

    /// The fields the credential picker shows of the claims or the proof statements, whose
    /// extents give A9's rows.
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    /// The transaction the credential authorizes: the entry bound to it (T4).
    pub fn transaction(&self) -> Option<&BoundTransaction> {
        self.transaction.as_ref()
    }
}

/// What the view is built from.
pub(crate) struct Sources<'s, 'a> {
    pub(crate) answered: &'s Wallet<'a>,
    pub(crate) transactions: &'s Transactions,
    pub(crate) display: &'s DisplayCache,
    pub(crate) language: &'s Locale,
    pub(crate) card_wording: &'s CardWording,
    pub(crate) background: &'s [CredentialId],
    pub(crate) transaction_data: TransactionData,
}

/// The view of each of `offers` that shows, in order. An offer whose members' or additions'
/// claims or proof statements do not show is left out, as the credential picker leaves it out:
/// the user consents only to what the wallet shows, and the other offers stay.
///
/// # Errors
///
/// [`PresentationError::Display`] with the first offer's display error when no offer shows,
/// and any other error of an offer.
pub(crate) fn offer_views(
    offers: &Offers,
    sources: &Sources<'_, '_>,
) -> Result<Vec<OfferView>, PresentationError> {
    let mut views = Vec::new();
    let mut unshown = None;
    for offer in offers.offers() {
        match offer_view(offer, sources) {
            Ok(view) => views.push(view),
            Err(PresentationError::Display(error)) => {
                if unshown.is_none() {
                    unshown = Some(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
    match unshown {
        Some(error) if views.is_empty() => Err(PresentationError::Display(error)),
        Some(_) | None => Ok(views),
    }
}

fn offer_view(offer: &Offer, sources: &Sources<'_, '_>) -> Result<OfferView, PresentationError> {
    let members = member_views(offer.members(), sources)?;
    let additions = offer
        .additions()
        .iter()
        .map(|addition| addition_view(addition, sources))
        .collect::<Result<Vec<_>, _>>()?;
    let fields = members
        .iter()
        .flat_map(MemberView::credentials)
        .flat_map(CredentialView::fields);
    let facts = DisplayFacts {
        presentability: presentability(&members, sources.background),
        transaction_data: sources.transaction_data,
        additions: Choice::of_additions(offer),
        subsets: Choice::of_subsets(offer),
        rows: Rows::of(fields),
        host: HostDisplay::Full,
    };
    Ok(OfferView {
        offer: offer.clone(),
        purpose: purpose::line(offer.purposes()),
        members,
        additions,
        unexamined: offer.unexamined(),
        facts,
    })
}

fn addition_view(
    addition: &Addition,
    sources: &Sources<'_, '_>,
) -> Result<AdditionView, PresentationError> {
    Ok(AdditionView {
        set: addition.set(),
        purpose: addition
            .purpose()
            .and_then(|p| purpose::line(std::slice::from_ref(p))),
        members: member_views(addition.members(), sources)?,
    })
}

/// Whether the wallet presents each credential of `members` from its background service.
fn presentability(members: &[MemberView], background: &[CredentialId]) -> Presentability {
    let presentable = members
        .iter()
        .flat_map(MemberView::credentials)
        .all(|credential| background.contains(&credential.entry.credential_id()));
    if presentable {
        Presentability::WithoutUi
    } else {
        Presentability::OnWalletUi
    }
}

/// The views of `members`, one group of presented credentials, each with the entry it binds
/// (T4).
fn member_views(
    members: &[Member],
    sources: &Sources<'_, '_>,
) -> Result<Vec<MemberView>, PresentationError> {
    let bindings = sources.transactions.bind(sources.answered, members)?;
    offered(sources.answered, members)?
        .iter()
        .map(|member| {
            let credentials = member
                .candidates
                .iter()
                .map(|&(_, candidate)| {
                    let bound = Bound::of(member.answers, candidate);
                    let transaction = bindings
                        .iter()
                        .find(|binding| binding.bound == bound)
                        .map(BoundTransaction::of);
                    credential_view(member, candidate, transaction, sources)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(MemberView {
                query_id: member.answers.id().clone(),
                credentials,
            })
        })
        .collect()
}

impl BoundTransaction {
    fn of(binding: &BoundEntry<'_>) -> Self {
        Self {
            entry: binding.entry.position(),
            view: binding.taken.view().clone(),
        }
    }
}

/// The view of `candidate`, a candidate of `member`, with the transaction bound to it.
fn credential_view(
    member: &Offered<'_, '_>,
    candidate: &Candidate<siros_credential::UsableCredential<'_>>,
    transaction: Option<BoundTransaction>,
    sources: &Sources<'_, '_>,
) -> Result<CredentialView, PresentationError> {
    let credential = candidate.credential().credential();
    let (shown, fields) = shown(member, candidate, sources)?;
    Ok(CredentialView {
        entry: credential.entry(),
        answer: candidate.answer().clone(),
        card: sources
            .display
            .card(credential, sources.language, sources.card_wording),
        shown,
        fields,
        transaction,
    })
}

/// What `candidate`, a candidate of `member`, shows: its claim rows or its proof statement
/// rows, and the credential picker's fields of them.
fn shown(
    member: &Offered<'_, '_>,
    candidate: &Candidate<siros_credential::UsableCredential<'_>>,
    sources: &Sources<'_, '_>,
) -> Result<(Shown, Vec<Field>), PresentationError> {
    Ok(match candidate.answer() {
        Answer::Claims(claims) => {
            let rows = sources.display.claim_rows(
                candidate.credential().credential(),
                claims.pointers(),
                sources.language,
            )?;
            let fields = rows.iter().map(Field::of_claim).collect();
            (Shown::Claims(rows), fields)
        }
        Answer::Proof(choice) => {
            let zkp = member
                .answers
                .zkp()
                .ok_or(Inconsistency::ZkpQuery(member.query))?;
            let (query, option) = (zkp.query().query(), zkp.option(choice)?);
            (
                Shown::Proof(verified_rows(query, option)?),
                proof::rows(query, option)?,
            )
        }
    })
}
