//! The request as the credential picker reads it: a DC API request entry whose protocol is one
//! of OpenID4VP 1.0, A.1, in the shape its label names, with its DCQL query.
//!
//! # Nothing here is verified
//!
//! A signed request's payload is decoded **without checking the signature**. The picker has
//! no crypto and no randomness, runs under a hard size budget in someone else's process, and
//! is not the trust boundary: the wallet runs intake (`crate::intake`, feature `crypto`) at
//! selection time, before anything is disclosed. The picker decides only which entries to draw.
//! Nothing read here may be treated as authenticated by anything downstream.

mod shape;

use serde_json::Value;
use siros_codec::json::JsonTextError;
use siros_codec::Base64Error;
use siros_dcql::{DcqlQuery, QueryError};

use crate::client_id::{ClientId, ClientIdError, ClientIdPrefix};
use crate::jws_rules::JwsRule;
use crate::parameters::{self, Carrier, DcApiEncoding, Metadata, Nonce, ParameterFault};
use crate::protocol::Protocol;
use crate::request::{
    AttestationFormat, RequestSignature, ResponseMode, TransactionDataInvalid, TransactionDataItem,
};
use shape::Shaped;

/// Why one protocol's request data yielded no request.
///
/// Each variant means "decline this entry", which lets the caller fall through to another
/// entry the verifier offered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum NoQuery {
    /// The entry carried no `data`.
    NoData,
    /// `data` had neither `dcql_query` nor anything shaped like a JWS.
    NoQueryAndNoRequest,
    /// `data.request` is present but is neither a string nor an object.
    RequestNotAJwsOrObject,
    /// A JWS JSON Serialization object is present but carries no string `payload`.
    JwsObjectHasNoPayload,
    /// The data carries a `request` under the unsigned protocol, or an inline query under a
    /// signed one: the label and the shape disagree.
    ShapeDoesNotMatchProtocol,
    /// `data.request` of a signed request is no compact JWS.
    NotACompactJws(#[source] CompactFault),
    /// The payload segment is no unpadded base64url the picker decodes.
    PayloadNotBase64url(#[source] PayloadFault),
    /// The payload decoded, but is not JSON.
    PayloadNotJson(#[source] JsonTextError),
    /// The payload is JSON but carries no `dcql_query`.
    PayloadHasNoDcqlQuery,
    /// A `dcql_query` was found but does not parse as DCQL.
    Malformed(#[source] QueryError),
    /// `transaction_data` is no non-empty array of strings (Section 5.1).
    TransactionData(#[source] TransactionDataInvalid),
    /// A request parameter breaks a rule intake applies without a key.
    Parameter(#[source] ParameterFault),
    /// A signed request's payload has no string `client_id` (A.2).
    ClientIdMissing,
    /// A signed request's `client_id` is no Client Identifier this wallet supports (Section
    /// 5.9).
    ClientId(#[source] ClientIdError),
    /// A signed request uses the `redirect_uri` prefix (Section 5.9.3).
    SignedRedirectUri,
    /// An `openid4vp-v1-multisigned` payload holds `client_id` (A.3.2.2).
    ClientIdInPayload,
    /// An `openid4vp-v1-multisigned` payload holds `verifier_info`, which travels in each
    /// signature's protected header (A.3.2.2).
    VerifierInfoInPayload,
    /// No signature of an `openid4vp-v1-multisigned` request can qualify: none keeps the JWS
    /// rules that need no key with a protected header naming a supported Client Identifier that
    /// signs (A.3.2.2).
    NoSignatureQualifies,
    /// A Request Object's JWS breaks a rule that needs no key, or a JWS JSON Serialization has
    /// no array `signatures`.
    Jws(#[source] JwsRule),
    /// A Request Object's protected header names a `typ` other than `oauth-authz-req+jwt`
    /// (RFC 9101, Section 10.8).
    TypMismatch,
    /// The protocol is none of the three of OpenID4VP 1.0, A.1.
    NoParser,
}

impl NoQuery {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoData => "no_data",
            Self::NoQueryAndNoRequest => "no_query_and_no_request",
            Self::RequestNotAJwsOrObject => "request_not_a_jws_or_object",
            Self::JwsObjectHasNoPayload => "jws_object_has_no_payload",
            Self::ShapeDoesNotMatchProtocol => "shape_does_not_match_protocol",
            Self::NotACompactJws(_) => "not_a_compact_jws",
            Self::PayloadNotBase64url(_) => "payload_not_base64url",
            Self::PayloadNotJson(_) => "payload_not_json",
            Self::PayloadHasNoDcqlQuery => "payload_has_no_dcql_query",
            Self::Malformed(_) => "dcql_query_malformed",
            Self::TransactionData(invalid) => invalid.code(),
            Self::Parameter(fault) => fault.code(),
            Self::ClientIdMissing => "client_id_missing",
            Self::ClientId(error) => error.code(),
            Self::SignedRedirectUri => "signed_redirect_uri",
            Self::ClientIdInPayload => "client_id_in_payload",
            Self::VerifierInfoInPayload => "verifier_info_in_payload",
            Self::NoSignatureQualifies => "no_verifiable_signature",
            Self::Jws(rule) => rule.code(),
            Self::TypMismatch => "typ_mismatch",
            Self::NoParser => "protocol_unsupported",
        }
    }

    /// One line for the picker's debug entry.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::NoData => "request entry has no `data`".into(),
            Self::NoQueryAndNoRequest => {
                "data has neither `dcql_query` nor a `request` to decode".into()
            }
            Self::RequestNotAJwsOrObject => {
                "data.request is neither a JWS string nor a JWS JSON object".into()
            }
            Self::JwsObjectHasNoPayload => {
                "the JWS JSON object has no string `payload` member".into()
            }
            Self::ShapeDoesNotMatchProtocol => {
                "the request shape does not match the protocol it is labelled with".into()
            }
            Self::NotACompactJws(_) => "data.request is not a compact JWS".into(),
            Self::PayloadNotBase64url(_) => "JWS payload is not unpadded base64url".into(),
            Self::PayloadNotJson(_) => "JWS payload is not JSON".into(),
            Self::PayloadHasNoDcqlQuery => "JWS payload has no `dcql_query`".into(),
            Self::Malformed(e) => format!("dcql_query failed to parse: {e}"),
            Self::TransactionData(_) => "transaction_data is no non-empty array of strings".into(),
            Self::Parameter(fault) => format!("request parameter refused: {}", fault.code()),
            Self::ClientIdMissing => "signed request has no string `client_id`".into(),
            Self::ClientId(error) => format!("client_id refused: {}", error.code()),
            Self::SignedRedirectUri => "signed request uses the redirect_uri prefix".into(),
            Self::ClientIdInPayload => "multisigned payload holds `client_id`".into(),
            Self::VerifierInfoInPayload => "multisigned payload holds `verifier_info`".into(),
            Self::NoSignatureQualifies => "no signature can qualify".into(),
            Self::Jws(rule) => format!("the JWS breaks a rule: {rule}"),
            Self::TypMismatch => "the Request Object's `typ` is not `oauth-authz-req+jwt`".into(),
            Self::NoParser => "no parser for this protocol in this build".into(),
        }
    }
}

/// How `data.request` of an `openid4vp-v1-signed` request fails to be a compact JWS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CompactFault {
    /// `request` is absent or not a string.
    #[error("`request` is absent or not a string")]
    NotString,
    /// The string has other than three segments (RFC 7515, Section 7.1).
    #[error("the string has other than three segments (RFC 7515, Section 7.1)")]
    Segments,
    /// The header segment is empty.
    #[error("the header segment is empty")]
    EmptyHeader,
    /// The payload segment is empty.
    #[error("the payload segment is empty")]
    EmptyPayload,
}

/// Why a JWS payload segment yields no bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PayloadFault {
    /// The segment is longer than the picker decodes.
    #[error("the segment is longer than the picker decodes")]
    TooLong,
    /// The segment is not unpadded base64url.
    #[error("the segment is not unpadded base64url")]
    Encoding(#[source] Base64Error),
}

/// One DC API request entry, read without verification (OpenID4VP 1.0, Appendix A).
///
/// Its existence guarantees a protocol of A.1 and a `data` in the shape that protocol names,
/// carrying a `dcql_query` that DCQL parses and, when present, a `transaction_data` that is a
/// non-empty array of strings. Every value comes from a payload whose signature nobody checked.
#[derive(Debug, Clone, PartialEq)]
pub struct UnverifiedRequest {
    protocol: Protocol,
    nonce: Nonce,
    encoding: DcApiEncoding,
    client: Option<ClientId>,
    expected_origins: Option<Vec<String>>,
    client_metadata: Option<Value>,
    verifier_info: Vec<AttestationFormat>,
    query: DcqlQuery,
    transaction_data: Vec<TransactionDataItem>,
}

/// The Client Identifier rules of a request: its Client Identifier, its `expected_origins`, its
/// `verifier_info` formats, and where its Verifier metadata comes from.
struct Client {
    client: Option<ClientId>,
    expected_origins: Option<Vec<String>>,
    verifier_info: Vec<AttestationFormat>,
    metadata: Metadata,
}

impl UnverifiedRequest {
    /// Reads one entry: its protocol `label` and its `data`.
    ///
    /// # Errors
    ///
    /// [`NoQuery`]: [`NoQuery::NoParser`] for a label outside A.1, otherwise what the data
    /// breaks.
    pub fn read(label: &str, data: &Value) -> Result<Self, NoQuery> {
        let protocol = Protocol::from_label(label).ok_or(NoQuery::NoParser)?;
        let shaped = shape::request_object(protocol, data)?;
        let members = shaped
            .object()
            .as_object()
            .ok_or(NoQuery::PayloadHasNoDcqlQuery)?;
        let parameter = NoQuery::Parameter;
        let carrier = match protocol {
            Protocol::Unsigned => Carrier::UnsignedData,
            Protocol::Signed | Protocol::Multisigned => Carrier::SignedObject,
        };
        let nonce = parameters::nonce(members, carrier).map_err(parameter)?;
        let mode = members.get("response_mode").and_then(Value::as_str);
        let encoding = DcApiEncoding::of(mode).map_err(parameter)?;
        let raw = members
            .get("dcql_query")
            .ok_or(NoQuery::PayloadHasNoDcqlQuery)?;
        let query = DcqlQuery::parse(raw).map_err(NoQuery::Malformed)?;
        let Client {
            client,
            expected_origins,
            verifier_info,
            metadata,
        } = client(&shaped, members, &query)?;
        let client_metadata = parameters::client_metadata(members, metadata).map_err(parameter)?;
        let transaction_data = match members.get("transaction_data") {
            None => Vec::new(),
            Some(entries) => {
                TransactionDataItem::list(entries).map_err(NoQuery::TransactionData)?
            }
        };
        Ok(Self {
            protocol,
            nonce,
            encoding,
            client,
            expected_origins,
            client_metadata,
            verifier_info,
            query,
            transaction_data,
        })
    }

    /// The first entry of the DC API request `request`, `{"requests": [{"protocol", "data"},
    /// …]}`, whose label `registered` accepts and whose data reads.
    ///
    /// The request is a list because one DC API call can offer the same request under several
    /// protocols. An entry that does not read is skipped, so a later readable one wins.
    #[must_use]
    pub fn first_registered(request: &[u8], registered: &dyn Fn(&str) -> bool) -> Option<Self> {
        serde_json::from_slice::<Value>(request)
            .ok()?
            .get("requests")?
            .as_array()?
            .iter()
            .find_map(|entry| {
                let label = entry.get("protocol")?.as_str()?;
                if !registered(label) {
                    return None;
                }
                Self::read(label, entry.get("data")?).ok()
            })
    }

    /// The protocol of the entry.
    #[must_use]
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// The request's `nonce`.
    #[must_use]
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// How the request arrived: a request under a signed protocol arrives as a JWS, whose
    /// signature intake verifies at selection.
    #[must_use]
    pub fn signature(&self) -> RequestSignature {
        if self.protocol.is_signed() {
            RequestSignature::Signed
        } else {
            RequestSignature::Unsigned
        }
    }

    /// The request's Response Mode: `dc_api` or `dc_api.jwt`.
    #[must_use]
    pub fn response_mode(&self) -> ResponseMode {
        self.encoding.mode()
    }

    /// The `format` of each `verifier_info` attestation, in the request's order (Section 5.1):
    /// the request object's, or of a multisigned request, the first protected header's that can
    /// qualify. Intake reads the header of the signature that qualifies.
    #[must_use]
    pub fn verifier_info_formats(&self) -> &[AttestationFormat] {
        &self.verifier_info
    }

    /// The `transaction_data` strings as received; empty when the request has none.
    #[must_use]
    pub fn transaction_data(&self) -> &[TransactionDataItem] {
        &self.transaction_data
    }

    /// The Client Identifier of a signed request; `None` for an unsigned one, whose
    /// `client_id` the Wallet ignores (A.2), and for a multisigned one, whose Client
    /// Identifiers are its signatures' (A.3.2.2).
    #[must_use]
    pub fn client_id(&self) -> Option<&ClientId> {
        self.client.as_ref()
    }

    /// The `expected_origins` of a signed request; `None` for an unsigned one, whose
    /// `expected_origins` the Wallet ignores (A.2).
    #[must_use]
    pub fn expected_origins(&self) -> Option<&[String]> {
        self.expected_origins.as_deref()
    }

    /// The request's `client_metadata`, when the Verifier metadata comes from the request;
    /// `None` for an `openid_federation` client, whose Trust Chain carries it (Section 5.9.3).
    #[must_use]
    pub fn client_metadata(&self) -> Option<&Value> {
        self.client_metadata.as_ref()
    }

    /// The request object's `dcql_query`.
    #[must_use]
    pub fn query(&self) -> &DcqlQuery {
        &self.query
    }
}

/// The Client Identifier rules intake applies before it verifies a signature, over the request
/// `shaped`, whose request object has the members `members` and the DCQL query `query`.
///
/// A signed payload names a supported Client Identifier, not of the `redirect_uri` prefix
/// (Sections 5.9, 5.9.3; A.2), and `expected_origins`. A multisigned payload names no
/// `client_id` and no `verifier_info`, which travel in each signature's protected header, and
/// `expected_origins` (A.3.2.2); its request reads when a protected header can qualify (see
/// [`Signer`]). The Verifier metadata comes from the request, except for an
/// `openid_federation` client, whose Trust Chain carries it: a signed request's, or one a
/// multisigned request's protected header that can qualify names.
///
/// # Errors
///
/// [`NoQuery`]: the Client Identifier rule the request breaks.
fn client(
    shaped: &Shaped<'_>,
    members: &serde_json::Map<String, Value>,
    query: &DcqlQuery,
) -> Result<Client, NoQuery> {
    let origins = || parameters::expected_origins(members).map_err(NoQuery::Parameter);
    let verifier_info =
        |value: Option<&Value>| parameters::verifier_info(value, query).map_err(NoQuery::Parameter);
    let metadata = |federation: bool| {
        if federation {
            Metadata::TrustChain(None)
        } else {
            Metadata::Request
        }
    };
    match shaped {
        Shaped::Unsigned(_) => Ok(Client {
            client: None,
            expected_origins: None,
            verifier_info: verifier_info(members.get("verifier_info"))?,
            metadata: Metadata::Request,
        }),
        Shaped::Signed(_) => {
            let text = members
                .get("client_id")
                .and_then(Value::as_str)
                .ok_or(NoQuery::ClientIdMissing)?;
            let client = ClientId::parse(text).map_err(NoQuery::ClientId)?;
            if client.prefix() == ClientIdPrefix::RedirectUri {
                return Err(NoQuery::SignedRedirectUri);
            }
            let federation = client.prefix() == ClientIdPrefix::OpenidFederation;
            Ok(Client {
                client: Some(client),
                expected_origins: Some(origins()?),
                verifier_info: verifier_info(members.get("verifier_info"))?,
                metadata: metadata(federation),
            })
        }
        Shaped::Multisigned { headers, .. } => {
            if members.contains_key("client_id") {
                return Err(NoQuery::ClientIdInPayload);
            }
            if members.contains_key("verifier_info") {
                return Err(NoQuery::VerifierInfoInPayload);
            }
            let expected_origins = Some(origins()?);
            let signers = signers(headers, query)?;
            let federation = signers
                .iter()
                .any(|signer| signer.client.prefix() == ClientIdPrefix::OpenidFederation);
            Ok(Client {
                client: None,
                expected_origins,
                verifier_info: signers.first.verifier_info,
                metadata: metadata(federation),
            })
        }
    }
}

/// A signature of a multisigned request that can qualify, read without verification: it keeps
/// the JWS rules that need no key, and its protected header names a supported Client
/// Identifier that signs, of a prefix other than `redirect_uri`, and a `verifier_info` that
/// keeps its rules (A.3.2.2; Sections 5.1, 5.9).
struct Signer {
    client: ClientId,
    verifier_info: Vec<AttestationFormat>,
}

/// The signatures of a multisigned request that can qualify, in their order: the first, and
/// the others.
struct Signers {
    first: Signer,
    rest: Vec<Signer>,
}

impl Signers {
    fn iter(&self) -> impl Iterator<Item = &Signer> {
        std::iter::once(&self.first).chain(&self.rest)
    }
}

/// The signatures of the protected headers `headers`, each of a signature that keeps the JWS
/// rules that need no key, that can qualify. Which one qualifies takes its verification, which
/// intake runs: with several, the picker reads what any of them admits.
///
/// # Errors
///
/// When none can qualify: the `verifier_info` rule of the first header with a Client
/// Identifier that signs, else [`NoQuery::NoSignatureQualifies`].
fn signers(
    headers: &[serde_json::Map<String, Value>],
    query: &DcqlQuery,
) -> Result<Signers, NoQuery> {
    let mut signers = Vec::new();
    let mut first_fault = None;
    for header in headers {
        let client = header
            .get("client_id")
            .and_then(Value::as_str)
            .and_then(|text| ClientId::parse(text).ok())
            .filter(|client| client.prefix() != ClientIdPrefix::RedirectUri);
        let Some(client) = client else {
            continue;
        };
        match parameters::verifier_info(header.get("verifier_info"), query) {
            Ok(verifier_info) => signers.push(Signer {
                client,
                verifier_info,
            }),
            Err(fault) => {
                first_fault.get_or_insert(fault);
            }
        }
    }
    let mut signers = signers.into_iter();
    let first = signers
        .next()
        .ok_or_else(|| first_fault.map_or(NoQuery::NoSignatureQualifies, NoQuery::Parameter))?;
    Ok(Signers {
        first,
        rest: signers.collect(),
    })
}

/// Why no entry of the DC API request `request` reads, one clause per entry.
///
/// `registered` is the same filter [`UnverifiedRequest::first_registered`] takes. The picker
/// shows this only when the wallet registered with its debug flag set.
#[must_use]
pub fn diagnose(request: &[u8], registered: &dyn Fn(&str) -> bool) -> String {
    let parsed: Value = match serde_json::from_slice(request) {
        Ok(v) => v,
        Err(e) => return format!("request ({} bytes) is not valid JSON: {e}", request.len()),
    };
    let Some(requests) = parsed.get("requests").and_then(|r| r.as_array()) else {
        return "request JSON has no `requests` array".to_string();
    };
    if requests.is_empty() {
        return "`requests` array is empty".to_string();
    }
    requests
        .iter()
        .map(|entry| entry_diagnosis(entry, registered))
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Why the request entry `entry` does not read, as one clause.
fn entry_diagnosis(entry: &Value, registered: &dyn Fn(&str) -> bool) -> String {
    let protocol = entry
        .get("protocol")
        .and_then(|p| p.as_str())
        .unwrap_or("<missing protocol>");
    if !registered(protocol) {
        return format!("{protocol}: not in registered profile");
    }
    let Some(data) = entry.get("data") else {
        return format!("{protocol}: {}", NoQuery::NoData.reason());
    };
    match UnverifiedRequest::read(protocol, data) {
        Ok(read) => format!(
            "{protocol}: dcql_query parsed ({} credential queries) - should not have reached here",
            read.query().credentials().len()
        ),
        Err(e) => format!("{protocol}: {}", e.reason()),
    }
}
