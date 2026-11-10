//! Reading the presentations of one query from a JSON `vp_token` (`zkp_req`, Section 6.1;
//! OpenID4VP 1.0, Section 8.1).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::{DecodeError, Engine as _};
use siros_openid4vp::ids::QueryId;
use siros_openid4vp::json::{JsonError, Node};
use siros_openid4vp::request::Multiplicity;

use crate::ids::PresentationIndex;

/// Why a `vp_token` gives no presentations for a query.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum VpTokenError {
    /// The text is no JSON with unique member names.
    NotJson(#[source] JsonError),
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
        error: DecodeError,
    },
}

impl VpTokenError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotJson(JsonError::Syntax(_)) | Self::NotObject => "response_not_object",
            Self::NotJson(JsonError::DuplicateMember { .. }) => "duplicate_member",
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
    query_id: &QueryId<'_>,
    multiplicity: Multiplicity,
) -> Result<Vec<Vec<u8>>, VpTokenError> {
    let token = Node::parse(vp_token).map_err(VpTokenError::NotJson)?;
    let Node::Object(members) = token else {
        return Err(VpTokenError::NotObject);
    };
    let entry = members
        .get(query_id.as_str())
        .ok_or(VpTokenError::QueryIdMissing)?;
    let Node::Array(list) = entry else {
        return Err(VpTokenError::NotArray);
    };
    match (list.len(), multiplicity) {
        (0, _) => return Err(VpTokenError::Empty),
        (1, _) | (_, Multiplicity::Many) => {}
        (_, Multiplicity::One) => return Err(VpTokenError::MultipleNotAllowed),
    }
    list.iter()
        .enumerate()
        .map(|(index, p)| {
            let index = PresentationIndex::new(index);
            let Node::String(text) = p else {
                return Err(VpTokenError::NotString { index });
            };
            URL_SAFE_NO_PAD
                .decode(text.as_bytes())
                .map_err(|error| VpTokenError::NotBase64url { index, error })
        })
        .collect()
}
