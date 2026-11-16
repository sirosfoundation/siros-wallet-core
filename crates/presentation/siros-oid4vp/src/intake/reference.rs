//! A request by reference (RFC 9101, Section 5.2; OpenID4VP 1.0, Section 5.10): the Request
//! Object intake needs, and the text the host obtains for it.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use siros_codec::url::HttpsUrl;

use crate::bound::{self, TooLarge};
use crate::client_id::ClientIdPrefix;
use crate::form::{self, FormBody};
use crate::values::WalletNonce;

/// The Request Object intake needs: the one `request_uri` serves, requested by
/// `request_uri_method`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUri {
    uri: HttpsUrl,
    method: RequestUriMethod,
}

impl RequestUri {
    pub(super) fn new(uri: HttpsUrl, method: RequestUriMethod) -> Self {
        Self { uri, method }
    }

    /// `request_uri`.
    #[must_use]
    pub fn uri(&self) -> &HttpsUrl {
        &self.uri
    }

    /// `request_uri_method`, with what a `post` sends.
    #[must_use]
    pub fn method(&self) -> &RequestUriMethod {
        &self.method
    }
}

/// `request_uri_method` (Section 5.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestUriMethod {
    /// `get`, the default.
    Get,
    /// `post`: the wallet sends these parameters, and the Request Object echoes the nonce.
    Post(WalletParameters),
}

impl RequestUriMethod {
    /// The `wallet_nonce` the Request Object echoes: that of a `post`.
    pub(super) fn echoed(&self) -> Option<&WalletNonce> {
        match self {
            Self::Get => None,
            Self::Post(parameters) => Some(&parameters.nonce),
        }
    }
}

/// The parameters of a `request_uri_method=post` request (Section 5.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletParameters {
    metadata: WalletMetadata,
    nonce: WalletNonce,
}

impl WalletParameters {
    /// The parameters of a wallet whose formats are `vp_formats_supported`, with the nonce
    /// `nonce`.
    pub(super) fn new(vp_formats_supported: &Map<String, Value>, nonce: WalletNonce) -> Self {
        Self {
            metadata: WalletMetadata::of(vp_formats_supported),
            nonce,
        }
    }

    /// `wallet_metadata`.
    #[must_use]
    pub fn wallet_metadata(&self) -> &WalletMetadata {
        &self.metadata
    }

    /// `wallet_nonce`.
    #[must_use]
    pub fn wallet_nonce(&self) -> &WalletNonce {
        &self.nonce
    }

    /// The form parameters `wallet_metadata`, as JSON text, and `wallet_nonce`.
    #[must_use]
    pub fn form(&self) -> FormBody {
        form::encode(&[
            ("wallet_metadata", &self.metadata.to_string()),
            ("wallet_nonce", self.nonce.as_str()),
        ])
    }
}

/// `wallet_metadata` (Section 10): the wallet's formats, and the Client Identifier Prefixes
/// and Request Object algorithm this core supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletMetadata(Map<String, Value>);

impl WalletMetadata {
    fn of(vp_formats_supported: &Map<String, Value>) -> Self {
        let prefixes = ClientIdPrefix::ALL.map(|prefix| Value::from(prefix.as_str()));
        Self(Map::from_iter([
            (
                "vp_formats_supported".to_owned(),
                Value::Object(vp_formats_supported.clone()),
            ),
            (
                "client_id_prefixes_supported".to_owned(),
                Value::Array(prefixes.to_vec()),
            ),
            (
                "request_object_signing_alg_values_supported".to_owned(),
                Value::Array(vec!["ES256".into()]),
            ),
        ]))
    }

    /// The metadata parameters.
    #[must_use]
    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }
}

/// The JSON text of the object.
impl fmt::Display for WalletMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Value::Object(self.0.clone()))
    }
}

/// A Request Object as the host obtained it from `request_uri`: a text of at most
/// [`Self::MAX_BYTES`] bytes, which intake reads as a JWS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RequestObjectText(String);

impl RequestObjectText {
    /// The most bytes of a Request Object intake reads.
    pub const MAX_BYTES: usize = 256 * 1024;

    /// The Request Object `text`.
    ///
    /// # Errors
    ///
    /// [`TooLarge`] for a text of more than [`Self::MAX_BYTES`] bytes.
    pub fn new(text: String) -> Result<Self, TooLarge> {
        bound::within(text.as_bytes(), Self::MAX_BYTES)?;
        Ok(Self(text))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RequestObjectText {
    type Error = TooLarge;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::new(text)
    }
}

impl From<RequestObjectText> for String {
    fn from(text: RequestObjectText) -> Self {
        text.0
    }
}
