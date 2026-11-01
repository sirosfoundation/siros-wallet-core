//! Core WMP types: the `wmp` envelope of every message, identity
//! assertions, relay entries, delegates, the session security mode, and the
//! capabilities map with its parameter types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

/// The protocol version of this implementation.
pub const VERSION: &str = "0.1";

/// The `wmp` envelope present in every WMP message.
///
/// Timestamps (`timestamp`, `expires_at`, `deliver_after`) are carried as
/// their RFC 3339 text until the session machinery needs typed comparison;
/// they are opaque to the envelope.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Metadata {
    /// The protocol version of the message, `MAJOR.MINOR`.
    #[serde(default)]
    pub version: String,
    /// The session the message belongs to.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_id: String,
    /// The sender's WMP identity.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sender: String,
    /// When the message was sent, RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// The token that proves the timestamp.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub timestamp_token: String,
    /// When the message expires, RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Whether the payload is encrypted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub encrypted: bool,
    /// The MLS epoch of the message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<i64>,
    /// The signature over the message.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    /// Identity assertions binding the sender to a legal identity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_assertions: Vec<IdentityAssertion>,
    /// Provenance entries for messages that traversed a relay.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_chain: Vec<RelayEntry>,
    /// A tracing identifier.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub trace_id: String,
    /// The delegated sender acting on behalf of the original sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_delegate: Option<SenderDelegate>,
    /// The earliest time the message may be delivered, RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliver_after: Option<String>,
}

/// An assertion binding a cryptographic identifier to a legal identity.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct IdentityAssertion {
    /// The type of the assertion.
    pub r#type: String,
    /// The format of the asserted credential.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub format: String,
    /// The verifiable presentation token carrying the assertion.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vp_token: String,
    /// The audience the presentation was created for.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub audience: String,
    /// The nonce binding the presentation to this exchange.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nonce: String,
    /// The claims the holder chose to disclose.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclosed_claims: Vec<String>,
    /// The certificate chain of the signer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub x5c: Vec<String>,
    /// Suggested trust frameworks for verifying the assertion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_hints: Vec<TrustHint>,
}

/// A suggested trust framework for verifying an identity assertion.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TrustHint {
    /// The trust framework.
    pub framework: String,
    /// The URL of the list of trusted entities.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub lote_url: String,
    /// The issuer's service identifier.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issuer_service_id: String,
    /// The trust anchor.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub trust_anchor: String,
    /// The entity statement.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub entity_statement: String,
    /// The root CA.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub root_ca: String,
    /// A framework-specific URI.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uri: String,
    /// The framework's validation endpoint.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub validation_endpoint: String,
}

/// A provenance entry recorded when a message traverses a relay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelayEntry {
    /// The relay's identity.
    pub relay: String,
    /// The relay's identifier for the message.
    pub relay_id: String,
    /// When the relay handled the message, RFC 3339.
    pub timestamp: String,
    /// The token that proves the timestamp.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub timestamp_token: String,
    /// The relay's signature over the message.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    /// The relay's class of service.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub service_class: String,
}

/// A delegated sender acting on behalf of the original sender.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SenderDelegate {
    /// The delegate's identifier.
    pub id: String,
    /// The delegate's identity assertions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_assertions: Vec<IdentityAssertion>,
    /// The authorization for the delegation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<DelegateAuthorization>,
}

/// The authorization for a sender delegate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DelegateAuthorization {
    /// The type of the authorization.
    pub r#type: String,
    /// The credential carrying the authorization.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub credential: String,
    /// The scopes the delegate may act in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    /// When the authorization expires.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub valid_until: String,
}

/// The session security configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SecurityMode {
    /// The security mode: for example `tls` or `mls`.
    pub mode: String,
    /// The minimum TLS version.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub min_tls_version: String,
    /// The cipher suites, by IANA number.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cipher_suites: Vec<i64>,
    /// The single cipher suite negotiated for the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<i64>,
    /// The MLS group information.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mls_group_info: String,
    /// The capabilities that must be encrypted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub encrypted_capabilities: Vec<String>,
}

/// The capabilities map: capability names to their raw parameter objects.
///
/// The map is ordered so the serialized form is deterministic, mirroring
/// go-wmp, whose JSON encoder sorts map keys.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities(pub BTreeMap<String, Box<RawValue>>);

impl PartialEq for Capabilities {
    fn eq(&self, other: &Self) -> bool {
        // `RawValue` has no `PartialEq`; compare the serialized JSON, so two
        // maps with the same members in the same shapes are equal.
        self.0.len() == other.0.len()
            && self.0.iter().all(|(name, value)| {
                other
                    .0
                    .get(name)
                    .is_some_and(|other_value| value.get() == other_value.get())
            })
    }
}

impl Capabilities {
    /// Parses the parameters of the `transaction_data` capability and reports
    /// whether it lists `version`.
    ///
    /// Absence of the capability, an unparsable value, or a list without the
    /// version all mean "not offered" — mirroring
    /// `wmp.Capabilities.OffersTransactionData`. Use it on what the peer
    /// **offered**, not on the negotiated result: negotiation may fall back
    /// to every server capability when a peer offers none, which would read
    /// as support the peer never claimed.
    pub fn offers_transaction_data(&self, version: i64) -> bool {
        let raw = match self.0.get(CAPABILITY_TRANSACTION_DATA) {
            Some(raw) => raw,
            None => return false,
        };
        match serde_json::from_str::<TransactionDataCap>(raw.get()) {
            Ok(offered) => offered.versions.contains(&version),
            Err(_) => false,
        }
    }
}

/// The capability a wallet offers when it can process OID4VP
/// `transaction_data` end to end: validate it against the attestation's type
/// metadata, show it to the user, and bind it into the presentation by
/// hashing each entry's original base64url string. A wallet that does not
/// offer it must not be sent `transaction_data`, because an implementation
/// that ignores the member signs the presentation without the hashes and
/// without the user seeing the transaction.
pub const CAPABILITY_TRANSACTION_DATA: &str = "transaction_data";

/// The first version of the `transaction_data` capability (OpenID4x profile
/// §2.3).
pub const TRANSACTION_DATA_VERSION_1: i64 = 1;

/// The parameters of the `transaction_data` capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionDataCap {
    /// The capability versions the wallet implements.
    pub versions: Vec<i64>,
    /// The `transaction_data_hashes_alg` names the wallet can compute, for
    /// example `sha-256`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hash_algs: Vec<String>,
}

/// The parameters of the `messaging` capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagingCap {
    /// The largest message the peer accepts.
    pub max_size: i64,
}

/// The parameters of the `flows` capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowsCap {
    /// The number of concurrent flows the peer supports.
    pub max_concurrent: i64,
}

/// The parameters of the `sign` capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignCap {
    /// The proof types the peer accepts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proof_types: Vec<String>,
}

/// The parameters of the `mcp` capability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpCap {
    /// Whether the peer offers tools.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tools: bool,
    /// Whether the peer offers resources.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub resources: bool,
    /// Whether the peer offers prompts.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub prompts: bool,
}

/// The parameters of the `relay` capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayCap {
    /// The relay destinations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<String>,
}

/// The parameters of the `offline` capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineCap {
    /// The maximum number of queued messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_queued: Option<i64>,
    /// The queue's time to live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<i64>,
}

/// The parameters of the `resolve` capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveCap {
    /// The resource types the peer resolves.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_types: Vec<String>,
}
