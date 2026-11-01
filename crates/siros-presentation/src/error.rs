//! Why a plan, a selection or a response failed. Each error has a stable code and the
//! OpenID4VP 1.0, Section 8.5 code the verifier receives.

use siros_credential::EntryRef;
use siros_dcql::PathError;
use siros_display::DisplayError;
use siros_mdoc::DisclosureError;
use siros_oid4vp::{ErrorCode, ResponseError};
use siros_sdjwt::KeyBindingError;
use siros_transaction_data::TransactionDataError;
use siros_trust::{ChainRefusal, Unadmitted};
use siros_wallet_state::KeyId;
use siros_zkp_req_nym_auth::presenter::{ProveError, Unanswerable};

use crate::ids::{AdditionIndex, OfferIndex, SetIndex};
use crate::inconsistency::Inconsistency;
use crate::matching::{ChoiceError, Failure};
use crate::plan::{DigestError, Unproven};
use crate::respond::{PickError, SignatureError, SubsetError};
use siros_dcql::QueryId;
use siros_transaction_data::EntryPosition;

/// Why the core gives no plan, no chosen offer or no response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum PresentationError {
    /// The wallet has no offer for the request, and why.
    NoOffer(#[from] Failure<Unadmitted<ChainRefusal>, Unproven>),
    /// An entry of `transaction_data`, or its binding to an offer, breaks a rule. The code is
    /// its own.
    TransactionData(#[from] TransactionDataError),
    /// The consent view cannot show a credential. The code is the display's.
    Display(#[from] DisplayError),
    /// The selection's plan digest does not read.
    Digest(#[from] DigestError),
    /// The selection was made on another plan (A4).
    DigestMismatch,
    /// The selection names an offer the plan lacks (A4).
    OfferUnknown(OfferIndex),
    /// The selection names an addition the offer lacks (A4).
    AdditionUnknown(AdditionIndex),
    /// The selection names two additions of this optional credential set (A3).
    AdditionSetRepeated(SetIndex),
    /// The selection names two additions that answer this Credential Query (A3).
    AdditionQueryRepeated(QueryId),
    /// The selection names a subset for a query the request has no `multiple` Credential Query
    /// of (A3).
    SubsetQuery(QueryId),
    /// The selection names a subset for a `multiple` query no chosen member answers (A3).
    SubsetMember(QueryId),
    /// The selection names two subsets for the member of this query (A3).
    SubsetRepeated(QueryId),
    /// A subset of a member's credentials is refused (A3).
    Subset(#[from] SubsetError),
    /// The selection leaves out the credential the transaction entry at `entry` binds to (T4).
    BoundCredentialOmitted {
        /// The entry's position in `transaction_data`.
        entry: EntryPosition,
        /// The credential, by `credentialId` and instance.
        credential: EntryRef,
    },
    /// The picked credential picker entries make no selection (K3).
    Pick(#[from] PickError),
    /// A fulfilment without the wallet's UI chose an offer that needs it (A9).
    WalletDisplayNeeded,
    /// A member's credential names no key pair.
    KeyIdMissing,
    /// A member's credential is an SD-JWT VC bound to no key: it has no `cnf`.
    HolderKeyMissing,
    /// The host reported no authentication factors for this key, whose KB-JWT carries `amr`
    /// (H3).
    KeyFactorsMissing(KeyId),
    /// The time is before 1970-01-01T00:00:00Z, which `iat` cannot carry.
    Time,
    /// The request names its audience neither by an origin nor by a Client Identifier.
    AudienceMissing,
    /// The plan contradicts the matching it was built from.
    Inconsistent(#[from] Inconsistency),
    /// A proof choice gives no option or usable pair of its query.
    Choice(#[from] ChoiceError),
    /// A nym_auth credential no longer passes its tests, or its seed does not open.
    Unproven(#[from] Unproven),
    /// A nym_auth credential does not answer its option.
    Unanswerable(#[from] Unanswerable),
    /// A claims path pointer of the plan selects nothing. The code is its own.
    Pointer(#[from] PathError),
    /// The KB-JWT claims collide (S4). The code is its own.
    KeyBinding(#[from] KeyBindingError),
    /// The mdoc elements are no disclosure (M2, M3). The code is its own.
    Disclosure(#[from] DisclosureError),
    /// The nym_auth proof failed. The code is its own.
    Prove(#[from] ProveError),
    /// The host's signatures do not answer the `Sign` effects (A5).
    Signature(#[from] SignatureError),
    /// The `vp_token` or its submission could not be built. The code is its own.
    Response(#[from] ResponseError),
}

impl PresentationError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoOffer(failure) => failure.code(),
            Self::TransactionData(e) => e.code(),
            Self::Display(e) => e.code(),
            Self::Digest(e) => e.code(),
            Self::DigestMismatch => "selection_digest_mismatch",
            Self::OfferUnknown(_) => "selection_offer_unknown",
            Self::AdditionUnknown(_) => "selection_addition_unknown",
            Self::AdditionSetRepeated(_) => "selection_addition_set_repeated",
            Self::AdditionQueryRepeated(_) => "selection_addition_query_repeated",
            Self::SubsetQuery(_) => "selection_subset_query",
            Self::SubsetMember(_) => "selection_subset_member",
            Self::SubsetRepeated(_) => "selection_subset_repeated",
            Self::Subset(e) => e.code(),
            Self::BoundCredentialOmitted { .. } => "selection_bound_credential_omitted",
            Self::Pick(e) => e.code(),
            Self::WalletDisplayNeeded => "wallet_display_needed",
            Self::KeyIdMissing => "key_id_missing",
            Self::HolderKeyMissing => "holder_key_missing",
            Self::KeyFactorsMissing(_) => "key_factors_missing",
            Self::Time => "time_before_epoch",
            Self::AudienceMissing => "audience_missing",
            Self::Inconsistent(e) => e.code(),
            Self::Choice(e) => e.code(),
            Self::Unproven(e) => e.code(),
            Self::Unanswerable(e) => e.code(),
            Self::Pointer(e) => e.code(),
            Self::KeyBinding(e) => e.code(),
            Self::Disclosure(e) => e.code(),
            Self::Prove(e) => e.code(),
            Self::Signature(e) => e.code(),
            Self::Response(e) => e.code(),
        }
    }

    /// The error the verifier receives (Section 8.5): `invalid_request` for a Credential Query
    /// that breaks a rule, the failure's own code when no offer remains,
    /// `invalid_transaction_data` for transaction data, and `access_denied` for every failure
    /// of the wallet, as `zkp_req.md`, Section 5 sends one.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::NoOffer(failure) => oid4vp_code(failure.error_code()),
            Self::TransactionData(e) => e.error_code(),
            Self::Prove(e) => oid4vp_code(e.error_code()),
            Self::Display(_)
            | Self::Digest(_)
            | Self::DigestMismatch
            | Self::OfferUnknown(_)
            | Self::AdditionUnknown(_)
            | Self::AdditionSetRepeated(_)
            | Self::AdditionQueryRepeated(_)
            | Self::SubsetQuery(_)
            | Self::SubsetMember(_)
            | Self::SubsetRepeated(_)
            | Self::Subset(_)
            | Self::BoundCredentialOmitted { .. }
            | Self::Pick(_)
            | Self::WalletDisplayNeeded
            | Self::KeyIdMissing
            | Self::HolderKeyMissing
            | Self::KeyFactorsMissing(_)
            | Self::Time
            | Self::AudienceMissing
            | Self::Inconsistent(_)
            | Self::Choice(_)
            | Self::Unproven(_)
            | Self::Unanswerable(_)
            | Self::Pointer(_)
            | Self::KeyBinding(_)
            | Self::Disclosure(_)
            | Self::Signature(_)
            | Self::Response(_) => ErrorCode::AccessDenied,
        }
    }
}

/// The OpenID4VP 1.0, Section 8.5 code of a `zkp_req.md`, Section 5 code.
fn oid4vp_code(code: siros_zkp_req::ErrorCode) -> ErrorCode {
    match code {
        siros_zkp_req::ErrorCode::InvalidRequest => ErrorCode::InvalidRequest,
        siros_zkp_req::ErrorCode::VpFormatsNotSupported => ErrorCode::VpFormatsNotSupported,
        siros_zkp_req::ErrorCode::AccessDenied => ErrorCode::AccessDenied,
    }
}
