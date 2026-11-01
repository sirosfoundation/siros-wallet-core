//! What the transaction data and response layers read of a request, without its crypto: its
//! `transaction_data` entries, its Response Mode, the formats of its `verifier_info`, and whether
//! it arrived signed.

use serde_json::Value;

/// A string of the `transaction_data` parameter, exactly as the request carried it (Section
/// 5.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionDataItem(String);

impl TransactionDataItem {
    /// The string `text`, as a request carries it.
    #[must_use]
    pub fn new(text: String) -> Self {
        Self(text)
    }

    /// The string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The entries of the `transaction_data` parameter `value`: a non-empty array of strings
    /// (Section 5.1).
    ///
    /// # Errors
    ///
    /// [`TransactionDataInvalid`] for any other value.
    pub fn list(value: &Value) -> Result<Vec<Self>, TransactionDataInvalid> {
        let entries = value.as_array().filter(|entries| !entries.is_empty());
        entries
            .ok_or(TransactionDataInvalid)?
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .map(|text| Self(text.to_owned()))
                    .ok_or(TransactionDataInvalid)
            })
            .collect()
    }
}

/// Why a `transaction_data` parameter is refused: it is no non-empty array of strings (Section
/// 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub struct TransactionDataInvalid;

impl TransactionDataInvalid {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        "transaction_data_invalid"
    }
}

/// The `format` of a `verifier_info` attestation (Section 5.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttestationFormat(String);

impl AttestationFormat {
    /// The format identifier `text`.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(text.to_owned())
    }

    /// The format identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The Response Mode of a verified request (Sections 8.2, 8.3.1; A.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseMode {
    /// `direct_post`.
    DirectPost,
    /// `direct_post.jwt`.
    DirectPostJwt,
    /// `direct_post.cwt` (`zkp_req.md`, Section 6.2).
    DirectPostCwt,
    /// `dc_api`.
    DcApi,
    /// `dc_api.jwt`.
    DcApiJwt,
}

impl ResponseMode {
    const ALL: [Self; 5] = [
        Self::DirectPost,
        Self::DirectPostJwt,
        Self::DirectPostCwt,
        Self::DcApi,
        Self::DcApiJwt,
    ];

    /// The Response Mode the `response_mode` value `name` names.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == name)
    }

    /// The `response_mode` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectPost => "direct_post",
            Self::DirectPostJwt => "direct_post.jwt",
            Self::DirectPostCwt => "direct_post.cwt",
            Self::DcApi => "dc_api",
            Self::DcApiJwt => "dc_api.jwt",
        }
    }
}

/// Whether a request arrived as a signed Request Object (RFC 9101).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestSignature {
    /// A Request Object whose signature intake verified.
    Signed,
    /// A request of a `redirect_uri` client, or an unsigned DC API request.
    Unsigned,
}
