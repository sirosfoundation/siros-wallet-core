//! Outcomes and error codes (`zkp_req`, Section 5), and the request rules of this document.

use std::fmt;

use siros_codec::member::{ArrayIndex, MemberFault};

use crate::ids::{FnIdError, ItemIndex, ReqSetIndex, ReturnHandleError};

/// The error code a Wallet sends for a Credential Query it cannot answer (Section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// The query breaks a rule of `zkp_req` or of the function catalogue.
    InvalidRequest,
    /// The Wallet has no usable pair for any option of the query (Section 1.3).
    VpFormatsNotSupported,
    /// No credential can answer, the User declines, or proving fails. Sent without
    /// `error_description`.
    AccessDenied,
}

impl ErrorCode {
    /// The code as OpenID4VP 1.0, Section 8.5 writes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::VpFormatsNotSupported => "vp_formats_not_supported",
            Self::AccessDenied => "access_denied",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What breaks the `meta` member a source format defines (Section 1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum TypeValueFault {
    /// The member breaks its rule.
    #[error("the member breaks its rule")]
    Member(#[source] MemberFault),
    /// The `type_values` list at this position breaks the rule of a non-empty array of
    /// strings.
    #[error(
        "the `type_values` list at position {0} breaks the rule of a non-empty array of strings"
    )]
    List(ArrayIndex, #[source] MemberFault),
}

/// Why a member does not hold an identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum IdentifierFault<E> {
    /// The member is absent.
    #[error("the member is absent")]
    Absent,
    /// The member is not a string.
    #[error("the member is not a string")]
    NotString,
    /// The string breaks the identifier's syntax.
    #[error("the string breaks the identifier's syntax")]
    Syntax(#[source] E),
}

/// Why a `return` member holds no handle. An absent `return` marks an assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ReturnFault {
    /// The member is not a string.
    #[error("the member is not a string")]
    NotString,
    /// The string breaks the handle's syntax.
    #[error("the string breaks the handle's syntax")]
    Syntax(#[source] ReturnHandleError),
}

/// Why an entry of `_req_sets` is no option (Section 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum OptionFault {
    /// The option is not an array.
    #[error("the option is not an array")]
    NotArray,
    /// The option is empty.
    #[error("the option is empty")]
    Empty,
    /// The entry at this position is not an unsigned integer.
    #[error("the entry at position {0} is not an unsigned integer")]
    NotInteger(ArrayIndex),
    /// The entry at this position is no index of `_req`.
    #[error("the entry at position {0} is no index of `_req`")]
    OutOfRange(ArrayIndex),
    /// The option names this `_req` item a second time.
    #[error("the option names `_req` item {0} a second time")]
    Repeated(ItemIndex),
}

/// A rule of `zkp_req` that a request breaks, with what breaks it. Each one makes the request
/// invalid ([`ErrorCode::InvalidRequest`]). The rules of OpenID4VP 1.0, Section 6 are DCQL's,
/// which parses the query first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum RequestRule {
    /// `format` is not `zkp_req`.
    FormatNotZkpReq,
    /// `claims` is present (Section 1.1). DCQL refuses `claim_sets` without `claims`.
    ClaimsPresent,
    /// `meta.source_format` is absent, not a string or empty (Section 1.1).
    SourceFormatInvalid(#[source] MemberFault),
    /// The `meta` member the source format defines breaks its rule (Section 1.1).
    TypeValueInvalid(#[source] TypeValueFault),
    /// `_req` is absent, not an array or empty (Section 2).
    ReqInvalid(#[source] MemberFault),
    /// A `_req` item is not an object (Section 2).
    ItemNotObject {
        /// The item's index.
        item: ItemIndex,
    },
    /// A `_req` item has a member other than `fn_id`, `params` and `return` (Section 2).
    ItemMemberUnknown {
        /// The item's index.
        item: ItemIndex,
    },
    /// `fn_id` is absent, not a string or empty (Section 2).
    FnIdInvalid {
        /// The item's index.
        item: ItemIndex,
        /// What breaks the rule.
        #[source]
        fault: IdentifierFault<FnIdError>,
    },
    /// `params` is not an object (Section 2).
    ParamsNotObject {
        /// The item's index.
        item: ItemIndex,
    },
    /// `return` is not a non-empty string of ASCII letters, digits, `_` and `-` (Section 2).
    ReturnInvalid {
        /// The item's index.
        item: ItemIndex,
        /// What breaks the rule.
        #[source]
        fault: ReturnFault,
    },
    /// `return` repeats the handle of an earlier item (Section 2).
    ReturnRepeated {
        /// The index of the item that repeats it.
        item: ItemIndex,
    },
    /// `_req_sets` is not a non-empty array (Section 2.1).
    ReqSetsInvalid(#[source] MemberFault),
    /// An option is not a non-empty array of `_req` indexes, each at most once (Section 2.1).
    OptionInvalid {
        /// The option's index.
        option: ReqSetIndex,
        /// What breaks the rule.
        #[source]
        fault: OptionFault,
    },
    /// `client_metadata` has no `vp_formats_supported.zkp_req` object (Section 1.2).
    FormatsMissing(#[source] MemberFault),
    /// `proof_backend_values` is not a non-empty array of strings (Section 1.2).
    ProofBackendValuesInvalid(#[source] MemberFault),
    /// `system_id_values` is not a non-empty array of strings (Section 1.2).
    SystemIdValuesInvalid(#[source] MemberFault),
}

impl RequestRule {
    /// A stable identifier of the rule, shared with the conformance vectors.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::FormatNotZkpReq => "format_not_zkp_req",
            Self::ClaimsPresent => "claims_present",
            Self::SourceFormatInvalid(_) => "source_format_invalid",
            Self::TypeValueInvalid(_) => "type_value_invalid",
            Self::ReqInvalid(_) => "req_invalid",
            Self::ItemNotObject { .. } => "item_not_object",
            Self::ItemMemberUnknown { .. } => "item_member_unknown",
            Self::FnIdInvalid { .. } => "fn_id_invalid",
            Self::ParamsNotObject { .. } => "params_not_object",
            Self::ReturnInvalid { .. } => "return_invalid",
            Self::ReturnRepeated { .. } => "return_repeated",
            Self::ReqSetsInvalid(_) => "req_sets_invalid",
            Self::OptionInvalid { .. } => "option_invalid",
            Self::FormatsMissing(_) => "formats_missing",
            Self::ProofBackendValuesInvalid(_) => "proof_backend_values_invalid",
            Self::SystemIdValuesInvalid(_) => "system_id_values_invalid",
        }
    }
}
