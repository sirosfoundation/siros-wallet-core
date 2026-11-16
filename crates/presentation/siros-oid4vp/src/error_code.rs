//! The error codes a Wallet returns to a Verifier (OpenID4VP 1.0, Section 8.5; RFC 6749,
//! Section 4.1.2.1).

use std::fmt;

/// An `error` value of an Authorization Error Response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// `invalid_request`: the request breaks a rule of OpenID4VP or of its Client Identifier
    /// Prefix.
    InvalidRequest,
    /// `invalid_scope`: the request asks through `scope`, which this wallet does not map to a
    /// DCQL query.
    InvalidScope,
    /// `access_denied`: no matching credentials, no consent, or no End-User authentication.
    AccessDenied,
    /// `vp_formats_not_supported`: none of the requested formats is supported.
    VpFormatsNotSupported,
    /// `invalid_request_uri_method`: `request_uri_method` is neither `get` nor `post`.
    InvalidRequestUriMethod,
    /// `invalid_transaction_data`: an entry of `transaction_data` breaks its type.
    InvalidTransactionData,
}

impl ErrorCode {
    /// The `error` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidScope => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::VpFormatsNotSupported => "vp_formats_not_supported",
            Self::InvalidRequestUriMethod => "invalid_request_uri_method",
            Self::InvalidTransactionData => "invalid_transaction_data",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
