//! The well-known configuration: its document types, the domain extraction
//! from every WMP identifier, and the discovery over an injected fetcher —
//! the mirror of go-wmp's `discovery.go`.
//!
//! go-wmp fetches `/.well-known/wmp-configuration` with `http.DefaultClient`;
//! this crate is sans-network, so [`discover_config`] takes the fetcher and
//! enforces the response limits itself.

use serde::{Deserialize, Serialize};

/// The maximum size of a well-known document: 1 MiB.
const MAX_CONFIG_BYTES: usize = 1 << 20;

/// A WMP well-known configuration document, served at
/// `/.well-known/wmp-configuration`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WellKnownConfig {
    /// The protocol versions the endpoint speaks.
    pub supported_versions: Vec<String>,
    /// The endpoints, keyed by name.
    pub endpoints: std::collections::BTreeMap<String, String>,
    /// The capabilities the endpoint offers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<serde_json::Value>,
    /// The identifier schemes the endpoint accepts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_schemes: Vec<String>,
    /// The security modes the endpoint accepts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_modes: Vec<String>,
    /// The URL of the MLS key packages.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mls_key_packages: String,
    /// The relay endpoint.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub relay: String,
    /// The identity providers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_providers: Vec<String>,
    /// The trust frameworks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_frameworks: Vec<String>,
    /// The ERDS metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erds: Option<ErdsMetadata>,
    /// The recipient's delivery preferences.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_metadata: Option<RecipientMetadata>,
}

/// Advertises ERDS (Electronic Registered Delivery Service) capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErdsMetadata {
    /// The consignment modes supported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consignment_modes: Vec<String>,
    /// The assurance levels supported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assurance_levels: Vec<String>,
    /// The policies supported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_policies: Vec<String>,
    /// Whether delegation is supported.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub delegation: bool,
    /// The evidence repository.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub evidence_repository: String,
    /// The evidence retention policy.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub evidence_retention: String,
    /// Whether scheduled delivery is supported.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub scheduled_delivery: bool,
}

/// Advertises a recipient's delivery preferences.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecipientMetadata {
    /// The accepted content types.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_content_types: Vec<String>,
    /// The maximum message size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_message_size: Option<i64>,
    /// The consignment preferences.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub consignment_preferences: String,
    /// Whether encryption is required.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub encryption_required: bool,
}

/// Why a discovery failed.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// The domain is empty or contains characters that could redirect the
    /// request elsewhere.
    #[error("wmp: invalid domain {0:?}")]
    InvalidDomain(String),
    /// The identifier names no domain.
    #[error("cannot extract domain from identifier {0:?}")]
    NoDomain(String),
    /// The fetcher failed; the underlying detail is the adapter's, and it is
    /// carried as received.
    #[error("fetch well-known: {0}")]
    Fetch(String),
    /// The document is not a well-known configuration.
    #[error("decode well-known: {0}")]
    Decode(String),
}

/// Extracts the domain from a WMP identifier for well-known resolution:
/// `did:web:`, `https://`, `x509:san:dns:` and `x509:san:uri:https://`
/// identifiers carry one; anything else answers an empty string.
pub fn extract_domain(identifier: &str) -> String {
    if identifier.starts_with("did:web:") {
        return parse_did_web(identifier).map_or_else(String::new, |(domain, _)| domain);
    }
    if let Some(rest) = identifier.strip_prefix("https://") {
        return host_of(rest).to_owned();
    }
    if let Some(rest) = identifier.strip_prefix("x509:san:dns:") {
        return rest.to_owned();
    }
    if let Some(rest) = identifier.strip_prefix("x509:san:uri:https://") {
        return host_of(rest).to_owned();
    }
    String::new()
}

/// The host of a URL: everything before the first path, query or fragment.
fn host_of(rest: &str) -> &str {
    match rest.find(['/', '?', '#']) {
        Some(idx) => &rest[..idx],
        None => rest,
    }
}

/// Safely constructs the well-known configuration URL for a domain,
/// rejecting domain values that contain path separators, query strings,
/// fragments, or userinfo that could redirect the request elsewhere.
pub fn build_well_known_url(domain: &str) -> Result<String, DiscoveryError> {
    if domain.is_empty() {
        return Err(DiscoveryError::InvalidDomain(String::new()));
    }
    if domain.contains(['/', '?', '#', '@', '\\']) {
        return Err(DiscoveryError::InvalidDomain(domain.to_owned()));
    }
    Ok(format!("https://{domain}/.well-known/wmp-configuration"))
}

/// Extracts the domain (and the sub-path, which well-known resolution never
/// follows) from a `did:web` identifier:
/// `did:web:example.com` → `example.com`;
/// `did:web:example.com:users:alice` → `example.com` and `users/alice`;
/// `did:web:example.com%3A8080` → `example.com:8080`.
///
/// Per the WMP spec's privacy principle (§7.5), per-user sub-path resolution
/// publicly exposes the user-to-provider binding; well-known resolution always
/// goes to the provider's domain-level configuration, and go-wmp's
/// `DiscoverConfigForDID` is deprecated in the same way — the mirror does not
/// carry it.
pub fn parse_did_web(did: &str) -> Option<(String, String)> {
    let rest = did.strip_prefix("did:web:")?;
    let mut parts = rest.split(':');
    let domain = parts.next().unwrap_or_default().replace("%3A", ":");
    if !is_valid_did_web_domain(&domain) {
        return None;
    }
    let path = parts.collect::<Vec<_>>().join("/");
    Some((domain, path))
}

/// Rejects domains that could redirect discovery to unexpected hosts — via
/// embedded path separators or userinfo, or a leading dot.
fn is_valid_did_web_domain(domain: &str) -> bool {
    !domain.is_empty() && !domain.contains(['/', '\\', '?', '#', '@']) && !domain.starts_with('.')
}

/// Fetches the WMP well-known configuration for a domain through `fetch`,
/// which receives the well-known URL and answers the response body. The body
/// is limited to [`MAX_CONFIG_BYTES`] and must decode as a configuration.
///
/// This is the primary discovery mechanism for all domain-based identifiers;
/// use [`extract_domain`] to get the domain from any WMP identifier.
pub fn discover_config(
    fetch: impl Fn(&str) -> Result<Vec<u8>, String>,
    domain: &str,
) -> Result<WellKnownConfig, DiscoveryError> {
    let url = build_well_known_url(domain)?;
    let body = fetch(&url).map_err(DiscoveryError::Fetch)?;
    if body.len() > MAX_CONFIG_BYTES {
        return Err(DiscoveryError::Fetch("well-known too large".to_owned()));
    }
    serde_json::from_slice(&body).map_err(|err| DiscoveryError::Decode(err.to_string()))
}

/// Fetches the well-known configuration for any WMP identifier by
/// extracting its domain. Errors when no domain can be extracted: the caller
/// falls back to session parameters or a profile resolver.
pub fn discover_config_for_identifier(
    fetch: impl Fn(&str) -> Result<Vec<u8>, String>,
    identifier: &str,
) -> Result<WellKnownConfig, DiscoveryError> {
    let domain = extract_domain(identifier);
    if domain.is_empty() {
        return Err(DiscoveryError::NoDomain(identifier.to_owned()));
    }
    discover_config(fetch, &domain)
}
