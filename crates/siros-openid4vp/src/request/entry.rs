//! `transaction_data` entries (OpenID4VP 1.0 §5.1): base64url without padding over UTF-8 JSON
//! with unique member names, a string `type` and a non-empty `credential_ids` of strings.

use std::borrow::Cow;

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use siros_explain::Explain;

use crate::ids::{NamedQueryId, TransactionType};
use crate::json::{Node, Object};

/// base64url without padding: its alphabet only, no `=`, no length of 1 modulo 4; trailing bits
/// past the last byte are ignored.
const BASE64URL: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

/// A `transaction_data` string that is no entry (rule C0, `invalid_transaction_data`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum Malformed {
    /// Characters outside base64url, or a length no base64url text has.
    #[error("not base64url without padding")]
    #[explain(id = "entry.not_base64_url")]
    NotBase64Url,
    /// The decoded bytes are no UTF-8.
    #[error("not base64url-encoded UTF-8")]
    #[explain(id = "entry.not_utf8")]
    NotUtf8,
    /// The decoded text is no JSON with unique member names.
    #[error("{0}")]
    #[explain(id = "entry.json")]
    Json(#[from] crate::json::JsonError),
    /// The JSON is no object.
    #[error("not a JSON object")]
    #[explain(id = "entry.not_object")]
    NotObject,
    /// `type` is no string.
    #[error("type is not a string")]
    #[explain(id = "entry.type")]
    Type,
    /// `credential_ids` is no non-empty array of strings.
    #[error("credential_ids is not a non-empty array of strings")]
    #[explain(id = "entry.credential_ids")]
    CredentialIds,
}

/// A `transaction_data` entry: the string as received, which every hash of it covers, the text it
/// decodes to, and its decoded members.
#[derive(Debug, Clone)]
pub struct Entry<'a> {
    raw: Cow<'a, str>,
    decoded: String,
    members: Object<'static>,
    kind: TransactionType<'static>,
    credential_ids: Vec<NamedQueryId<'static>>,
}

impl<'a> Entry<'a> {
    /// Decodes an entry.
    pub fn decode(raw: Cow<'a, str>) -> Result<Self, Malformed> {
        let bytes = BASE64URL
            .decode(raw.as_bytes())
            .map_err(|_| Malformed::NotBase64Url)?;
        let text = String::from_utf8(bytes).map_err(|_| Malformed::NotUtf8)?;
        let Node::Object(members) = Node::parse(&text)?.into_owned() else {
            return Err(Malformed::NotObject);
        };
        let kind = members
            .get("type")
            .and_then(Node::as_str)
            .map(|kind| TransactionType::parse(kind.to_owned()))
            .ok_or(Malformed::Type)?
            .map_err(|_| Malformed::Type)?;
        let credential_ids = members
            .get("credential_ids")
            .and_then(Node::as_array)
            .filter(|ids| !ids.is_empty())
            .and_then(|ids| {
                ids.iter()
                    .map(|id| {
                        id.as_str()
                            .and_then(|id| NamedQueryId::parse(id.to_owned()).ok())
                    })
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(Malformed::CredentialIds)?;
        Ok(Self {
            raw,
            decoded: text,
            members,
            kind,
            credential_ids,
        })
    }

    /// The string as received.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The UTF-8 JSON text the string decodes to, which a hash over the decoded entry covers.
    #[must_use]
    pub fn decoded(&self) -> &str {
        &self.decoded
    }

    /// The decoded object.
    #[must_use]
    pub fn members(&self) -> &Object<'static> {
        &self.members
    }

    /// The transaction data type.
    #[must_use]
    pub fn kind(&self) -> &TransactionType<'static> {
        &self.kind
    }

    /// The `credential_ids`, as received.
    #[must_use]
    pub fn credential_ids(&self) -> &[NamedQueryId<'static>] {
        &self.credential_ids
    }
}
