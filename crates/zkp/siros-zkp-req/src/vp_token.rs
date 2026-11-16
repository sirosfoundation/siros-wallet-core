//! Reading the presentations of one query from a JSON `vp_token` (`zkp_req`, Section 6.1;
//! OpenID4VP 1.0, Section 8.1).

use siros_codec::json::{Json, JsonFault};
use siros_codec::{base64url, Base64Error};
use siros_dcql::{Multiplicity, QueryId};

use crate::ids::PresentationIndex;

/// Why a `vp_token` gives no presentations for a query.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum VpTokenError {
    /// The strict reader refuses the text.
    NotJson(#[source] JsonFault),
    /// The JSON value is no object.
    NotObject,
    /// The object has no entry for the query's `id`.
    QueryIdMissing,
    /// The entry is not an array.
    NotArray,
    /// The entry is an empty array.
    Empty,
    /// The entry holds several presentations and the query does not set `multiple`.
    MultipleNotAllowed,
    /// A presentation is not a string.
    NotString {
        /// Its position in the entry.
        index: PresentationIndex,
    },
    /// A presentation is not base64url without padding (RFC 4648, Section 5).
    NotBase64url {
        /// Its position in the entry.
        index: PresentationIndex,
        /// What breaks the encoding.
        #[source]
        error: Base64Error,
    },
}

impl VpTokenError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotJson(JsonFault::Read(_)) | Self::NotObject => "response_not_object",
            Self::NotJson(JsonFault::RepeatedMember(_)) => "duplicate_member",
            Self::QueryIdMissing => "query_id_missing",
            Self::NotArray => "presentations_not_array",
            Self::Empty => "presentations_empty",
            Self::MultipleNotAllowed => "presentations_multiple_not_allowed",
            Self::NotString { .. } => "presentation_not_string",
            Self::NotBase64url { .. } => "presentation_not_base64url",
        }
    }
}

/// The CBOR presentations that answer `query_id` in the JSON `vp_token` text. In JSON, each
/// `ZkpPresentation` is the base64url, without padding, of its CBOR encoding.
///
/// # Errors
///
/// [`VpTokenError`]: the first rule the `vp_token` breaks for this query.
pub fn presentations_of(
    vp_token: &str,
    query_id: &QueryId,
    multiplicity: Multiplicity,
) -> Result<Vec<Vec<u8>>, VpTokenError> {
    let Json::Object(members) =
        Json::parse_unique(vp_token.as_bytes()).map_err(VpTokenError::NotJson)?
    else {
        return Err(VpTokenError::NotObject);
    };
    let entry = members
        .iter()
        .find(|(name, _)| query_id == name)
        .map(|(_, value)| value)
        .ok_or(VpTokenError::QueryIdMissing)?;
    let Json::Array(list) = entry else {
        return Err(VpTokenError::NotArray);
    };
    match (list.len(), multiplicity) {
        (0, _) => return Err(VpTokenError::Empty),
        (1, _) | (_, Multiplicity::Several) => {}
        (_, Multiplicity::One) => return Err(VpTokenError::MultipleNotAllowed),
    }
    list.iter()
        .enumerate()
        .map(|(index, p)| {
            let index = PresentationIndex::new(index);
            let Json::String(text) = p else {
                return Err(VpTokenError::NotString { index });
            };
            base64url::decode(text).map_err(|error| VpTokenError::NotBase64url { index, error })
        })
        .collect()
}
