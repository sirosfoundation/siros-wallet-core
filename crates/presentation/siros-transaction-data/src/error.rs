//! Why transaction data refuses a request. Each refusal has a stable code and the OpenID4VP 1.0,
//! Section 8.5 code a verifier receives.

use std::str::Utf8Error;

use siros_codec::json::{JsonFault, ReadFault};
use siros_codec::member::MemberFault;
use siros_codec::Base64Error;
use siros_dcql::QueryId;
use siros_oid4vp::ErrorCode;

use crate::hash::HashesAlgFault;
use crate::select::Exclusion;
use crate::sets::SetsFault;

siros_codec::position!(
    /// The position of an entry in the request's `transaction_data`.
    pub EntryPosition
);

/// A member of a `transaction_data` entry (OpenID4VP 1.0, Section 5.1; PaSO Core, Section 7.1;
/// PaSO Proof Metadata, Section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryMember {
    /// `type`.
    Type,
    /// `credential_ids`.
    CredentialIds,
    /// `payload`.
    Payload,
    /// `metadata`: the ad-hoc metadata JWT.
    Metadata,
    /// `transaction_data_hashes_alg`.
    HashesAlg,
}

impl EntryMember {
    /// The member's name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Type => "type",
            Self::CredentialIds => "credential_ids",
            Self::Payload => "payload",
            Self::Metadata => "metadata",
            Self::HashesAlg => "transaction_data_hashes_alg",
        }
    }
}

/// Why an entry of `transaction_data` does not read (T1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum EntryRefusal {
    /// The entry is not base64url without padding (OpenID4VP 1.0, Sections 1.2 and 5.1).
    NotBase64url(#[source] Base64Error),
    /// The entry's bytes are no UTF-8 text.
    NotUtf8(#[source] Utf8Error),
    /// The entry's text is no JSON document the strict reader holds: no JSON, a number beyond
    /// binary64, nesting deeper than [`MAX_DEPTH`](siros_codec::json::MAX_DEPTH), or an object
    /// that repeats a member name.
    NotJson(#[source] JsonFault),
    /// The entry's JSON value is no object.
    NotJsonObject,
    /// A member breaks its rule.
    Member(EntryMember, #[source] MemberFault),
    /// `type` is the empty string.
    TypeEmpty,
    /// `credential_ids` is empty.
    CredentialIdsEmpty,
    /// This `credential_ids` element names no Credential Query of the DCQL query.
    CredentialIdUnknown(String),
    /// This Credential Query, which `credential_ids` names, sets
    /// `require_cryptographic_holder_binding` to `false` (OpenID4VP 1.0, B.3).
    HolderBindingNotRequired(QueryId),
    /// `transaction_data_hashes_alg` is refused (B.3.3.1).
    HashesAlg(#[source] HashesAlgFault),
    /// The entry holds this member, which no specification of transaction data defines.
    MemberUnknown(String),
}

impl EntryRefusal {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotBase64url(_) => "transaction_data_not_base64url",
            Self::NotJson(JsonFault::RepeatedMember(_)) => "transaction_data_duplicate_key",
            Self::NotJson(JsonFault::Read(ReadFault::TooDeep)) => "transaction_data_too_deep",
            Self::NotJson(JsonFault::Read(ReadFault::TooLong)) => "transaction_data_too_long",
            Self::NotUtf8(_)
            | Self::NotJson(JsonFault::Read(
                ReadFault::Text(_) | ReadFault::NumberUnrepresentable,
            ))
            | Self::NotJsonObject => "transaction_data_not_json_object",
            Self::Member(_, MemberFault::Absent) => "transaction_data_member_missing",
            Self::Member(..) => "transaction_data_member_wrong_type",
            Self::TypeEmpty | Self::CredentialIdsEmpty => "transaction_data_member_invalid",
            Self::CredentialIdUnknown(_) => "transaction_data_credential_id_unknown",
            Self::HolderBindingNotRequired(_) => "transaction_data_holder_binding_not_required",
            Self::HashesAlg(fault) => fault.code(),
            Self::MemberUnknown(_) => "transaction_data_member_unknown",
        }
    }
}

/// Why transaction data refuses a request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum TransactionDataError {
    /// The entry at this position does not read.
    Entry(EntryPosition, #[source] EntryRefusal),
    /// The credential sets break a rule of PaSO Core, Section 7.4.1.
    CredentialSets(#[source] SetsFault),
    /// The entry at this position has a type the wallet knows from no source for any candidate
    /// credential, and the first match leaves a credential it targets unserved: each such
    /// credential with why it takes no entry (OpenID4VP 1.0, Section 5.1; PaSO Core, Section
    /// 7.4.2).
    TypeUnknown(EntryPosition, Vec<Exclusion>),
    /// The request arrived unsigned, and the entry at this position is PaSO-targeted or a
    /// credential takes it under a definition of PaSO metadata (PaSO Core, Section 3).
    Unsigned(EntryPosition),
    /// No Credential Query an entry targets has a candidate, and no offer remains: the
    /// referenced credentials are not available in the wallet (OpenID4VP 1.0, Section 8.5).
    CredentialUnavailable,
    /// The first match excluded every candidate of the queries the entries target: each
    /// credential with why it takes no entry (PaSO Core, Section 7.4.2, step 4).
    NoCompatibleCredential(Vec<Exclusion>),
}

impl TransactionDataError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Entry(_, refusal) => refusal.code(),
            Self::CredentialSets(fault) => fault.code(),
            Self::TypeUnknown(..) => "transaction_data_type_unknown",
            Self::Unsigned(_) => "transaction_data_request_unsigned",
            Self::CredentialUnavailable => "transaction_data_credential_unavailable",
            Self::NoCompatibleCredential(_) => "transaction_data_no_compatible_credential",
        }
    }

    /// The error of OpenID4VP 1.0, Section 8.5 a verifier receives: `invalid_request` for an
    /// unsigned request, `invalid_transaction_data` for every other refusal.
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Unsigned(_) => ErrorCode::InvalidRequest,
            Self::Entry(..)
            | Self::CredentialSets(_)
            | Self::TypeUnknown(..)
            | Self::CredentialUnavailable
            | Self::NoCompatibleCredential(_) => ErrorCode::InvalidTransactionData,
        }
    }
}
